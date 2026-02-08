package ratelimit

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/invenlore/api.gateway/pkg/auth"
	"github.com/invenlore/api.gateway/pkg/metrics"
	"github.com/invenlore/core/pkg/config"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GroupConfig struct {
	Name  string
	Limit Limit
}

type Middleware struct {
	limiter     Limiter
	resolver    IPResolver
	groups      map[string]GroupConfig
	exemptPaths map[string]struct{}
	metrics     *metrics.GatewayMetrics
}

func NewMiddleware(cfg *config.RateLimitConfig, resolver IPResolver, limiter Limiter, metricsCollector *metrics.GatewayMetrics) *Middleware {
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	groups := map[string]GroupConfig{
		"auth": {
			Name: "auth",
			Limit: Limit{
				RPS:    cfg.Auth.RPS,
				Burst:  cfg.Auth.Burst,
				Period: cfg.Period,
			},
		},
		"admin": {
			Name: "admin",
			Limit: Limit{
				RPS:    cfg.Admin.RPS,
				Burst:  cfg.Admin.Burst,
				Period: cfg.Period,
			},
		},
		"swagger": {
			Name: "swagger",
			Limit: Limit{
				RPS:    cfg.Swagger.RPS,
				Burst:  cfg.Swagger.Burst,
				Period: cfg.Period,
			},
		},
		"other": {
			Name: "other",
			Limit: Limit{
				RPS:    cfg.Other.RPS,
				Burst:  cfg.Other.Burst,
				Period: cfg.Period,
			},
		},
	}

	return &Middleware{
		limiter:     limiter,
		resolver:    resolver,
		groups:      groups,
		exemptPaths: parseExemptPaths(cfg.ExemptPaths),
		metrics:     metricsCollector,
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	if m == nil {
		return next
	}

	if next == nil {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil {
			if _, ok := m.exemptPaths[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		ip, ok := m.resolver.Resolve(r)
		if !ok || strings.TrimSpace(ip) == "" {
			m.reportDrop("bad_ip", routeGroup(r))

			writeRateLimitError(w, r, "rate limit: invalid client ip", time.Second)
			return
		}

		group := routeGroup(r)
		cfg := m.groups[group]
		key := "rl:" + group + ":" + ip

		decision, err := m.limiter.Allow(r.Context(), key, cfg.Limit)
		if err != nil {
			m.reportDrop("redis_error", group)

			writeRateLimitError(w, r, "rate limit: backend error", time.Second)
			return
		}

		if !decision.Allowed {
			m.reportDrop("exceeded", group)

			setRateLimitHeaders(w, cfg.Limit, decision)
			writeRateLimitError(w, r, "rate limit exceeded", decision.RetryAfter)
			return
		}

		setRateLimitHeaders(w, cfg.Limit, decision)
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) reportDrop(reason, group string) {
	if m == nil || m.metrics == nil {
		return
	}

	m.metrics.IncRateLimitDrop(reason, group)
}

func parseExemptPaths(raw string) map[string]struct{} {
	paths := make(map[string]struct{})

	for part := range strings.SplitSeq(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}

		paths[trimmed] = struct{}{}
	}

	return paths
}

func routeGroup(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "other"
	}

	path := r.URL.Path
	if path == "/swagger" || strings.HasPrefix(path, "/swagger/") || path == "/api.swagger.json" {
		return "swagger"
	}

	if strings.HasPrefix(path, "/v1/admin/") {
		return "admin"
	}

	if strings.HasPrefix(path, "/v1/auth/") || path == "/login" {
		return "auth"
	}

	return "other"
}

func setRateLimitHeaders(w http.ResponseWriter, limit Limit, decision Decision) {
	if w == nil {
		return
	}

	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.RPS))

	if decision.Remaining >= 0 {
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	}

	if !decision.ResetAt.IsZero() {
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.ResetAt.Unix(), 10))
	}
}

func writeRateLimitError(w http.ResponseWriter, r *http.Request, message string, retryAfter time.Duration) {
	if w == nil {
		return
	}

	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
	}

	st := status.New(codes.ResourceExhausted, message)
	auth.WriteErrorResponse(w, r, st)
}
