package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/auth"
	"github.com/invenlore/api.gateway/pkg/logger"
	"github.com/invenlore/api.gateway/pkg/utils"
	"github.com/invenlore/core/pkg/config"
	corelogger "github.com/invenlore/core/pkg/logger"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func NewHTTPServer(ctx context.Context, cfg *config.AppConfig) (*http.Server, net.Listener, func(), error) {
	var (
		loggerEntry = logrus.WithField("scope", "httpServer")
		listenAddr  = net.JoinHostPort(cfg.HTTP.Host, cfg.HTTP.Port)
	)

	loggerEntry.Info("starting http server...")

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	errorMapper := &auth.ErrorMapper{Logger: logrus.WithField("scope", "http.error")}

	mux := runtime.NewServeMux(
		runtime.WithErrorHandler(errorMapper.Handler),
		runtime.WithMetadata(func(_ context.Context, r *http.Request) metadata.MD {
			pairs := make([]string, 0, 8)

			if rid := r.Header.Get(logger.RequestIDHeader); rid != "" {
				pairs = append(pairs, "x-request-id", rid)
			}

			if userID := r.Header.Get(auth.HeaderUserID); userID != "" {
				pairs = append(pairs, "x-user-id", userID)
			}

			if roles := r.Header.Get(auth.HeaderUserRoles); roles != "" {
				pairs = append(pairs, "x-roles", roles)
			}

			if perms := r.Header.Get(auth.HeaderUserPerms); perms != "" {
				pairs = append(pairs, "x-perms-global", perms)
			}

			if scopes := r.Header.Get(auth.HeaderUserScopes); scopes != "" {
				pairs = append(pairs, "x-scopes", scopes)
			}

			if idempotency := r.Header.Get(auth.HeaderIdempotency); idempotency != "" {
				pairs = append(pairs, "x-idempotency-key", idempotency)
			}

			if len(pairs) == 0 {
				return nil
			}

			return metadata.Pairs(pairs...)
		}),
	)

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(
			corelogger.ClientRequestIDInterceptor,
			corelogger.ClientLoggingInterceptor,
		),
		grpc.WithChainStreamInterceptor(
			corelogger.ClientStreamInterceptor,
		),
	}

	var (
		connMu          sync.RWMutex
		conns           = make(map[string]*ServiceConnectionInfo)
		identityConn    *grpc.ClientConn
		identityConnErr error
	)

	for _, service := range cfg.GRPCServices {
		s := service

		sci := &ServiceConnectionInfo{
			Config:        s,
			Mux:           mux,
			Registered:    false,
			HealthTimeout: cfg.ServiceHealthTimeout,
		}

		connMu.Lock()
		conns[s.Name] = sci
		connMu.Unlock()

		sci.StartHealthCheck(ctx, dialOpts)
	}

	identityConn, identityConnErr = dialIdentityConn(cfg.GRPCServices, dialOpts)
	if identityConnErr != nil {
		loggerEntry.WithError(identityConnErr).Error("identity jwks provider disabled")
	}

	var authHandler http.Handler = utils.NewCombinedHandler(ctx, mux)

	if identityConn != nil {
		jwksProvider := auth.NewIdentityJWKSProvider(identity_v1.NewIdentityInternalServiceClient(identityConn))
		jwksCache := auth.NewJWKSCache(jwksProvider, cfg.Auth.JWKSCacheTTL)
		jwksFetcher := auth.NewJWKSCacheFetcher(jwksCache)

		middleware := auth.NewMiddleware(auth.MiddlewareConfig{
			JWKSFetcher:  jwksFetcher,
			AllowedSkew:  cfg.Auth.JWTAllowedSkew,
			RequireToken: true,
			PublicPaths: []string{
				"/v1/auth/register",
				"/v1/auth/login",
				"/v1/auth/refresh",
				"/v1/auth/logout",
			},
		})

		authHandler = middleware.Handler(authHandler)
	}

	httpHandler := logger.AccessLogMiddleware(authHandler)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
	}

	cleanup := func() {
		connMu.RLock()

		list := make([]*ServiceConnectionInfo, 0, len(conns))
		for _, sci := range conns {
			list = append(list, sci)
		}

		connMu.RUnlock()

		for _, sci := range list {
			sci.Close()
		}

		if identityConn != nil {
			_ = identityConn.Close()
		}

		loggerEntry.Trace("all gRPC client connections closed")
	}

	return server, ln, cleanup, nil
}

func dialIdentityConn(services []*config.GRPCService, dialOpts []grpc.DialOption) (*grpc.ClientConn, error) {
	var identityAddress string

	for _, service := range services {
		if service != nil && service.Name == "IdentityService" {
			identityAddress = service.Address
			break
		}
	}

	if identityAddress == "" {
		return nil, fmt.Errorf("identity service address not configured")
	}

	return grpc.NewClient(identityAddress, dialOpts...)
}
