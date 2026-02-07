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

	"github.com/invenlore/api.gateway/internal/transport"
	gatewaymetrics "github.com/invenlore/api.gateway/pkg/metrics"
	"github.com/invenlore/core/pkg/config"
	coremetrics "github.com/invenlore/core/pkg/metrics"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
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

	appCfg := cfg.GetConfig()
	serviceName := appCfg.ServiceName
	if serviceName == "" {
		serviceName = "gateway"
	}
	serviceVersion := appCfg.ServiceVersion
	if serviceVersion == "" {
		serviceVersion = "unknown"
	}

	loggerEntry.WithFields(logrus.Fields{
		"service": serviceName,
		"version": serviceVersion,
		"env":     appCfg.AppEnv,
	}).Info("gateway configuration loaded")

	metricsRegistry := coremetrics.NewRegistry(serviceName, appCfg.AppEnv, serviceVersion)
	metricsCollector := gatewaymetrics.NewGatewayMetrics(metricsRegistry)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", metricsRegistry.Handler())

	metricsSrv, metricsLn, err := coremetrics.StartMetricsServer(appCfg.GetMetricsConfig(), metricsMux)
	if err != nil {
		loggerEntry.Fatalf("metrics server init failed: %v", err)
	}

	httpSrv, httpLn, httpCleanup, err := transport.NewHTTPServer(ctx, cfg.GetConfig(), metricsCollector)
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
		loggerEntry.Infof("metrics server serving on %s...", metricsSrv.Addr)

		if err := metricsSrv.Serve(metricsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("metrics serve failed: %w", err)
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
		_ = metricsSrv.Shutdown(stopCtx)

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
