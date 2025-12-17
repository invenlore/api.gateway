package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/config"
	"github.com/invenlore/api.gateway/pkg/logger"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func StartHTTPServer(ctx context.Context, cfg *config.ServerConfig, errChan chan error) (*http.Server, net.Listener, error) {
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

	for _, service := range cfg.GRPCServices {
		wg.Add(1)

		go func(s config.GRPCService) {
			defer wg.Done()

			conn, err := grpc.NewClient(s.Address, dialOpts...)
			if err != nil {
				logrus.Errorf("failed to dial gRPC service %s at %s: %v, this service will not be available", s.Name, s.Address, err)

				return
			}

			if err := s.Register(ctx, mux, conn); err != nil {
				logrus.Errorf("failed to register gRPC service handler for %s: %v, this service will not be available", s.Name, err)
				conn.Close()

				return
			}

			logrus.Infof("successfully connected and registered gRPC service: %s", s.Name)
		}(service)
	}

	wg.Wait()

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
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

		logrus.Info("gRPC client pool closed")
	}()

	return server, ln, nil
}
