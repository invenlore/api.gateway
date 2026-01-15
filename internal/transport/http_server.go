package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/logger"
	"github.com/invenlore/api.gateway/pkg/utils"
	"github.com/invenlore/core/pkg/config"
	corelogger "github.com/invenlore/core/pkg/logger"
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

	mux := runtime.NewServeMux(
		runtime.WithMetadata(func(_ context.Context, r *http.Request) metadata.MD {
			if rid := r.Header.Get(logger.RequestIDHeader); rid != "" {
				return metadata.Pairs("x-request-id", rid)
			}

			return nil
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
		connMu sync.RWMutex
		conns  = make(map[string]*ServiceConnectionInfo)
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

	httpHandler := logger.AccessLogMiddleware(utils.NewCombinedHandler(ctx, mux))

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

		loggerEntry.Trace("all gRPC client connections closed")
	}

	return server, ln, cleanup, nil
}
