package metrics

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	coremetrics "github.com/invenlore/core/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type GatewayMetrics struct {
	httpRequests   *prometheus.CounterVec
	httpDuration   *prometheus.HistogramVec
	grpcRequests   *prometheus.CounterVec
	grpcDuration   *prometheus.HistogramVec
	authDenied     *prometheus.CounterVec
	jwksRefresh    *prometheus.CounterVec
	jwksAgeSeconds prometheus.Gauge
}

func NewGatewayMetrics(reg *coremetrics.Registry) *GatewayMetrics {
	if reg == nil {
		return nil
	}

	httpRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "invenlore_gateway_http_requests_total",
			Help: "Total number of HTTP requests served by the gateway.",
		},
		[]string{"route_group", "method", "status"},
	)

	httpDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "invenlore_gateway_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: coremetrics.DefaultBuckets,
		},
		[]string{"route_group", "method", "status"},
	)

	grpcRequests := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "invenlore_gateway_grpc_client_requests_total",
			Help: "Total number of gRPC upstream requests from gateway.",
		},
		[]string{"upstream", "method", "code"},
	)

	grpcDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "invenlore_gateway_grpc_client_handling_seconds",
			Help:    "Duration of gRPC upstream requests from gateway.",
			Buckets: coremetrics.DefaultBuckets,
		},
		[]string{"upstream", "method", "code"},
	)

	authDenied := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "invenlore_gateway_auth_denied_total",
			Help: "Total number of denied auth requests.",
		},
		[]string{"reason"},
	)

	jwksRefresh := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "invenlore_gateway_jwks_refresh_total",
			Help: "Total JWKS refresh attempts.",
		},
		[]string{"result"},
	)

	jwksAge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "invenlore_gateway_jwks_age_seconds",
			Help: "Age of the JWKS cache in seconds.",
		},
	)

	reg.Registerer.MustRegister(httpRequests, httpDuration, grpcRequests, grpcDuration, authDenied, jwksRefresh, jwksAge)

	return &GatewayMetrics{
		httpRequests:   httpRequests,
		httpDuration:   httpDuration,
		grpcRequests:   grpcRequests,
		grpcDuration:   grpcDuration,
		authDenied:     authDenied,
		jwksRefresh:    jwksRefresh,
		jwksAgeSeconds: jwksAge,
	}
}

func (m *GatewayMetrics) HTTPMiddleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}

	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		lrw := &responseWriter{ResponseWriter: w}
		next.ServeHTTP(lrw, r)

		status := lrw.status
		if status == 0 {
			status = http.StatusOK
		}

		path := ""
		if r != nil && r.URL != nil {
			path = r.URL.Path
		}

		method := "UNKNOWN"
		if r != nil {
			method = r.Method
		}

		group := routeGroup(path)
		code := fmt.Sprintf("%d", status)

		m.httpRequests.WithLabelValues(group, method, code).Inc()
		m.httpDuration.WithLabelValues(group, method, code).Observe(time.Since(start).Seconds())
	})
}

func (m *GatewayMetrics) GRPCClientInterceptor(upstream string) grpc.UnaryClientInterceptor {
	if m == nil {
		return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
	}

	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()

		err := invoker(ctx, method, req, reply, cc, opts...)
		code := status.Code(err).String()

		m.grpcRequests.WithLabelValues(upstream, coremetrics.NormalizeGRPCMethod(method), code).Inc()
		m.grpcDuration.WithLabelValues(upstream, coremetrics.NormalizeGRPCMethod(method), code).Observe(time.Since(start).Seconds())

		return err
	}
}

func (m *GatewayMetrics) IncAuthDenied(reason string) {
	if m == nil || reason == "" {
		return
	}

	m.authDenied.WithLabelValues(reason).Inc()
}

func (m *GatewayMetrics) ObserveJWKSRefresh(success bool) {
	if m == nil {
		return
	}

	result := "error"
	if success {
		result = "ok"
	}

	m.jwksRefresh.WithLabelValues(result).Inc()
}

func (m *GatewayMetrics) SetJWKSCacheAge(age time.Duration) {
	if m == nil {
		return
	}

	m.jwksAgeSeconds.Set(age.Seconds())
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	if w.status == 0 {
		w.status = statusCode
	}

	if w.ResponseWriter != nil {
		w.ResponseWriter.WriteHeader(statusCode)
	}
}

func routeGroup(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "other"
	}

	if path == "/health" {
		return "health"
	}

	if path == "/swagger" || strings.HasPrefix(path, "/swagger/") || path == "/api.swagger.json" {
		return "swagger"
	}

	if path == "/login" {
		return "auth"
	}

	if strings.HasPrefix(path, "/v1/auth/oauth/") {
		return "oauth"
	}

	if strings.HasPrefix(path, "/v1/auth/") {
		return "auth"
	}

	if strings.HasPrefix(path, "/v1/admin/") {
		return "admin"
	}

	if strings.HasPrefix(path, "/v1/wiki/") {
		return "wiki"
	}

	if strings.HasPrefix(path, "/v1/media/") {
		return "media"
	}

	return "other"
}
