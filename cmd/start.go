package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/invenlore/api.gateway/internal/transport"
	"github.com/invenlore/core/pkg/config"
	"github.com/sirupsen/logrus"
)

func Start() {
	loggerEntry := logrus.WithField("scope", "gateway")
	loggerEntry.Info("gateway starting...")

	cfg, err := config.Config()
	if err != nil {
		loggerEntry.Fatalf("failed to load gateway configuration: %v", err)
	}

	baseCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	g, ctx := errgroup.WithContext(baseCtx)

	httpSrv, httpLn, httpCleanup, err := transport.NewHTTPServer(ctx, cfg.GetConfig())
	if err != nil {
		loggerEntry.Fatalf("http server init failed: %v", err)
	}

	healthSrv, healthLn, err := transport.NewHealthServer(cfg.GetHealthConfig())
	if err != nil {
		_ = httpLn.Close()

		if httpCleanup != nil {
			httpCleanup()
		}

		loggerEntry.Fatalf("health server init failed: %v", err)
	}

	g.Go(func() error {
		loggerEntry.Infof("http server serving on %s...", httpSrv.Addr)

		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http serve failed: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		loggerEntry.Infof("health server serving on %s...", healthSrv.Addr)

		if err := healthSrv.Serve(healthLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("health serve failed: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		<-ctx.Done()

		loggerEntry.Trace("attempting graceful shutdown...")

		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = healthSrv.Shutdown(stopCtx)
		_ = httpSrv.Shutdown(stopCtx)

		if httpCleanup != nil {
			httpCleanup()
		}

		loggerEntry.Info("clean gateway shutdown complete")
		return nil
	})

	if err := g.Wait(); err != nil {
		loggerEntry.Errorf("gateway stopped with error: %v", err)

		os.Exit(1)
	}

	loggerEntry.Debug("gateway stopped gracefully")
}
