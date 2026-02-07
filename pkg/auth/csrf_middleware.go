package auth

import (
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type CSRFMiddleware struct{}

type CSRFMetrics interface {
	IncAuthDenied(reason string)
}

type CSRFMiddlewareWithMetrics struct {
	Metrics CSRFMetrics
}

func (m CSRFMiddleware) Handler(next http.Handler) http.Handler {
	return CSRFMiddlewareWithMetrics{Metrics: nil}.Handler(next)
}

func (m CSRFMiddlewareWithMetrics) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if source, ok := AuthSourceFromContext(r.Context()); !ok || source != AuthSourceCookie {
			next.ServeHTTP(w, r)
			return
		}

		csrfCookie, err := r.Cookie(CookieCSRFToken)
		if err != nil || csrfCookie.Value == "" {
			if m.Metrics != nil {
				m.Metrics.IncAuthDenied("csrf")
			}

			WriteErrorResponse(w, r, statusUnauthenticated("csrf token missing"))
			return
		}

		csrfHeader := r.Header.Get(HeaderCSRFTOKEN)
		if csrfHeader == "" || csrfHeader != csrfCookie.Value {
			if m.Metrics != nil {
				m.Metrics.IncAuthDenied("csrf")
			}

			WriteErrorResponse(w, r, statusPermissionDenied("csrf token invalid"))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func statusPermissionDenied(message string) *status.Status {
	return status.New(codes.PermissionDenied, message)
}

func statusUnauthenticated(message string) *status.Status {
	return status.New(codes.Unauthenticated, message)
}
