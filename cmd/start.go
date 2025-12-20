package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/invenlore/api.gateway/internal/transport"
	"github.com/invenlore/core/pkg/config"
	"github.com/sirupsen/logrus"
)

func Start() {
	var (
		errChan  = make(chan error, 2)
		stopChan = make(chan os.Signal, 1)

		httpServer           *http.Server = nil
		httpServerListener   net.Listener = nil
		healthServer         *http.Server = nil
		healthServerListener net.Listener = nil

		serviceErr error = nil
	)

	logrus.Info("gateway starting...")

	cfg, err := config.LoadConfig()
	if err != nil {
		logrus.Fatalf("failed to load gateway configuration: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		var err error

		httpServer, httpServerListener, err = transport.StartHTTPServer(ctx, cfg, errChan)
		if err != nil {
			if httpServerListener != nil {
				httpServerListener.Close()
			}

			errChan <- fmt.Errorf("http server failed to start: %w", err)
		}
	}()

	go func() {
		var err error

		healthServer, healthServerListener, err = transport.StartHealthServer(ctx, cfg, errChan)
		if err != nil {
			if healthServerListener != nil {
				healthServerListener.Close()
			}

			errChan <- fmt.Errorf("health server failed to start: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		serviceErr = err
		logrus.Errorf("service startup error: %v", serviceErr)

	case <-stopChan:
		logrus.Debug("received stop signal")
	}

	defer func() {
		logrus.Debug("attempting service graceful shutdown...")

		if healthServer != nil {
			logrus.Info("stopping health server...")

			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := healthServer.Shutdown(stopCtx); err != nil {
				logrus.Errorf("health server shutdown error: %v", err)
			} else {
				logrus.Info("health server stopped gracefully")
			}
		} else {
			logrus.Warn("health server was not started")
		}

		if httpServer != nil {
			logrus.Info("stopping http server...")

			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := httpServer.Shutdown(stopCtx); err != nil {
				logrus.Errorf("http server shutdown error: %v", err)
			} else {
				logrus.Info("http server stopped gracefully")
			}
		} else {
			logrus.Warn("http server was not started")
		}

		logrus.Info("clean service shutdown complete")

		if serviceErr != nil {
			os.Exit(1)
		}
	}()
}
