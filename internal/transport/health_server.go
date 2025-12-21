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

func NewHealthServer(_ context.Context, cfg *config.AppConfig) (*http.Server, net.Listener, error) {
	listenAddr := net.JoinHostPort(cfg.Health.Host, cfg.Health.Port)
	logrus.Info("starting health server on ", listenAddr)

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /health", health.GetHealthHandler())

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
	}

	return server, ln, nil
}
