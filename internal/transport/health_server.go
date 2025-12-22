package transport

import (
	"fmt"
	"net"
	"net/http"

	"github.com/invenlore/core/pkg/config"
	"github.com/invenlore/core/pkg/health"
	"github.com/sirupsen/logrus"
)

func NewHealthServer(cfg *config.HealthServerConfig) (*http.Server, net.Listener, error) {
	var (
		loggerEntry = logrus.WithField("scope", "health")
		listenAddr  = net.JoinHostPort(cfg.Host, cfg.Port)
	)

	loggerEntry.Info("starting health server...")

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /health", health.GetHealthHandler())

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}

	return server, ln, nil
}
