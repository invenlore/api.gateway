package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/auth"
	"github.com/invenlore/api.gateway/pkg/logger"
	"github.com/invenlore/api.gateway/pkg/ui"
	"github.com/invenlore/api.gateway/pkg/utils"
	"github.com/invenlore/core/pkg/config"
	corelogger "github.com/invenlore/core/pkg/logger"
	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
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
				"/v1/auth/oauth/github/start",
				"/v1/auth/oauth/github/callback",
				"/login",
			},
		})

		authHandler = middleware.Handler(authHandler)
	}

	loginHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		loginTemplate := template.Must(template.New("login").Parse(ui.LoginHTML()))
		_ = loginTemplate.Execute(w, nil)
	})

	csrfMiddleware := auth.CSRFMiddleware{}

	loginMux := http.NewServeMux()
	loginMux.Handle("/login", loginHandler)
	loginMux.Handle("/v1/auth/oauth/github/start", oauthStartHandler(authHandler))
	loginMux.Handle("/v1/auth/oauth/github/callback", oauthCallbackHandler(authHandler, cfg))

	loginMux.Handle("/", csrfMiddleware.Handler(authHandler))

	httpHandler := logger.AccessLogMiddleware(loginMux)

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

type responseCapture struct {
	header     http.Header
	statusCode int
	body       bytes.Buffer
}

func newResponseCapture() *responseCapture {
	return &responseCapture{header: make(http.Header)}
}

func (r *responseCapture) Header() http.Header {
	return r.header
}

func (r *responseCapture) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

func (r *responseCapture) Write(p []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}

	return r.body.Write(p)
}

func (r *responseCapture) writeTo(w http.ResponseWriter) {
	for key, values := range r.header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	if r.statusCode != 0 {
		w.WriteHeader(r.statusCode)
	}

	if r.body.Len() > 0 {
		_, _ = io.Copy(w, bytes.NewReader(r.body.Bytes()))
	}
}

func oauthStartHandler(authHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(r.Context())

		query := req.URL.Query()
		query.Set("provider", "OAUTH_PROVIDER_GITHUB")

		req.URL.RawQuery = query.Encode()

		responseRecorder := newResponseCapture()
		authHandler.ServeHTTP(responseRecorder, req)
		if responseRecorder.statusCode == 0 {
			responseRecorder.statusCode = http.StatusOK
		}
		if responseRecorder.statusCode >= 300 {
			responseRecorder.writeTo(w)
			return
		}
		if responseRecorder.body.Len() == 0 {
			responseRecorder.writeTo(w)
			return
		}

		var payload identity_v1.StartOAuthResponse
		if err := protojson.Unmarshal(responseRecorder.body.Bytes(), &payload); err != nil {
			responseRecorder.writeTo(w)
			return
		}
		if strings.TrimSpace(payload.AuthorizationUrl) == "" {
			responseRecorder.writeTo(w)
			return
		}
		http.Redirect(w, r, payload.AuthorizationUrl, http.StatusFound)
	})
}

func oauthCallbackHandler(authHandler http.Handler, cfg *config.AppConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := r.Clone(r.Context())

		query := req.URL.Query()
		query.Set("provider", "OAUTH_PROVIDER_GITHUB")

		req.URL.RawQuery = query.Encode()

		responseRecorder := newResponseCapture()
		authHandler.ServeHTTP(responseRecorder, req)

		if responseRecorder.statusCode == 0 {
			responseRecorder.statusCode = http.StatusOK
		}

		if responseRecorder.statusCode >= 300 {
			responseRecorder.writeTo(w)
			return
		}

		if responseRecorder.body.Len() == 0 {
			responseRecorder.writeTo(w)
			return
		}

		var payload identity_v1.CompleteOAuthResponse
		if err := protojson.Unmarshal(responseRecorder.body.Bytes(), &payload); err != nil {
			responseRecorder.writeTo(w)
			return
		}

		setAuthCookies(w, &payload, cfg.AppEnv)
		redirect := payload.RedirectUri

		if redirect == "" {
			redirect = "/swagger/"
		}

		http.Redirect(w, r, redirect, http.StatusFound)
	})
}

func setAuthCookies(w http.ResponseWriter, payload *identity_v1.CompleteOAuthResponse, appEnv config.AppEnv) {
	if payload == nil {
		return
	}

	if strings.TrimSpace(payload.AccessToken) != "" {
		http.SetCookie(w, buildCookieHTTPOnly(auth.CookieAccessToken, payload.AccessToken, "/", appEnv))
	}

	if strings.TrimSpace(payload.RefreshToken) != "" {
		http.SetCookie(w, buildCookieHTTPOnly(auth.CookieRefreshToken, payload.RefreshToken, "/v1/auth/refresh", appEnv))
	}

	csrf := randomToken(32)
	http.SetCookie(w, buildCookieCSRF(auth.CookieCSRFToken, csrf, "/", appEnv))
}

func buildCookieHTTPOnly(name, value, path string, appEnv config.AppEnv) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: true,
		Secure:   appEnv == config.AppEnvProduction,
		SameSite: http.SameSiteLaxMode,
	}
}

func buildCookieCSRF(name, value, path string, appEnv config.AppEnv) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		HttpOnly: false,
		Secure:   appEnv == config.AppEnvProduction,
		SameSite: http.SameSiteLaxMode,
	}
}

func randomToken(length int) string {
	buf := make([]byte, length)
	_, _ = rand.Read(buf)

	return base64.RawURLEncoding.EncodeToString(buf)
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
