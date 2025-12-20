package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/utils"
	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/logger"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func StartHTTPServer(
	ctx context.Context,
	cfg *config.AppConfig,
	errChan chan error,
) (
	*http.Server,
	net.Listener,
	error,
) {
	var wg sync.WaitGroup

	listenAddr := net.JoinHostPort(cfg.HTTP.Host, cfg.HTTP.Port)
	logrus.Info("starting http server on ", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	mux := runtime.NewServeMux()

	unaryClientInterceptors := []grpc.UnaryClientInterceptor{
		logger.ClientRequestIDInterceptor,
		logger.ClientLoggingInterceptor,
	}

	streamClientInterceptors := []grpc.StreamClientInterceptor{
		logger.ClientStreamInterceptor,
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(unaryClientInterceptors...),
		grpc.WithChainStreamInterceptor(streamClientInterceptors...),
	}

	serviceConnections := make(map[string]*ServiceConnectionInfo)

	for _, service := range cfg.GRPCServices {
		wg.Add(1)

		go func(s config.GRPCService) {
			defer wg.Done()

			sci := &ServiceConnectionInfo{
				Config:        s,
				Mux:           mux,
				Registered:    false,
				HealthTimeout: cfg.ServiceHealthTimeout,
			}

			serviceConnections[s.Name] = sci
			sci.StartHealthCheck(ctx, dialOpts)
		}(service)
	}

	wg.Wait()

	combinedHandler := utils.NewCombinedHandler(ctx, mux)
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           combinedHandler,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
	}

	go func() {
		logrus.Infof("http server serving on %s", listenAddr)

		if serveErr := server.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			errChan <- fmt.Errorf("http server failed to serve: %w", serveErr)
		}

		for _, sci := range serviceConnections {
			if sci.Cancel != nil {
				sci.Cancel()
			}

			if sci.Conn != nil {
				sci.Conn.Close()
			}
		}

		logrus.Debug("all gRPC client connections closed")
	}()

	return server, ln, nil
}
