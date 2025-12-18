package transport

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/logger"
	third_party "github.com/invenlore/proto"
	"github.com/invenlore/proto/pkg/user"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func getSwaggerUIHandler() (http.Handler, error) {
	swaggerSubFS, err := third_party.GetSwaggerUISubFS()
	if err != nil {
		return nil, fmt.Errorf("couldn't get swagger sub filesystem: %v", err)
	}

	mime.AddExtensionType(".svg", "image/svg+xml")

	return http.StripPrefix("/swagger/", http.FileServer(http.FS(swaggerSubFS))), nil
}

func StartHTTPServer(ctx context.Context, cfg *config.ServerConfig, errChan chan error) (*http.Server, net.Listener, error) {
	var (
		swaggerJSONBytes = third_party.GetSwaggerJSON()
		wg               sync.WaitGroup
	)

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
			var healthErr error

			defer wg.Done()

			conn, err := grpc.NewClient(s.Address, dialOpts...)
			if err != nil {
				logrus.Errorf("failed to dial gRPC service %s at %s: %v, this service will not be available", s.Name, s.Address, err)

				return
			}

			checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
			defer checkCancel()

			switch s.Name {
			case "UserService":
				client := user.NewUserServiceClient(conn)
				_, healthErr = client.HealthCheck(checkCtx, &user.HealthRequest{})

			default:
				logrus.Warnf("skipping health check for unknown service: %s, assuming it will be registered", s.Name)
				healthErr = nil
			}

			if healthErr != nil {
				if status.Code(healthErr) == codes.DeadlineExceeded || errors.Is(healthErr, context.DeadlineExceeded) {
					logrus.Errorf("health check for gRPC service %s at %s timed out after 5s, service is unavailable", s.Name, s.Address)
				} else {
					logrus.Errorf("health check failed for gRPC service %s at %s: %v, service will be unavailable", s.Name, s.Address, healthErr)
				}

				conn.Close()
				return
			} else {
				logrus.Infof("health check for gRPC service %s at %s succeded, service is available", s.Name, s.Address)
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

	swaggerHandler, swaggerHandlerError := getSwaggerUIHandler()
	if swaggerHandlerError != nil {
		logrus.Errorf("can't get swagger handler: %v", swaggerHandlerError)
	}

	server := &http.Server{
		Addr: listenAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api.swagger.json" {
				w.Header().Set("Content-Type", "application/json")
				w.Write(swaggerJSONBytes)

				return
			}

			if r.URL.Path == "/swagger" {
				http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)

				return
			}

			if strings.HasPrefix(r.URL.Path, "/api/") {
				mux.ServeHTTP(w, r)

				return
			}

			if swaggerHandlerError == nil {
				swaggerHandler.ServeHTTP(w, r)

				return
			}
		}),
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
