package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/health"
	"github.com/sirupsen/logrus"
)

func StartHealthServer(
	ctx context.Context,
	cfg *config.AppConfig,
	errChan chan error,
) (
	*http.Server,
	net.Listener,
	error,
) {
	listenAddr := net.JoinHostPort(cfg.Health.Host, cfg.Health.Port)
	logrus.Info("starting health server on ", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("/health", health.GetHealthHandler())

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
	}

	go func() {
		logrus.Infof("health server serving on %s", listenAddr)

		if serveErr := server.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			errChan <- fmt.Errorf("health server failed to serve: %w", serveErr)
		}
	}()

	return server, ln, nil
}
