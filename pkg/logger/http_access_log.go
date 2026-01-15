package logger

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const RequestIDHeader = "X-Request-Id"

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *loggingResponseWriter) WriteHeader(code int) {
	// to not "superfluous response.WriteHeader".
	if w.status != 0 {
		return
	}

	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *loggingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}

	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)

	return n, err
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *loggingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *loggingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}

	return h.Hijack()
}

func AccessLogMiddleware(next http.Handler) http.Handler {
	loggerEntryBase := logrus.WithField("scope", "http.access")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		reqID := r.Header.Get(RequestIDHeader)
		if reqID == "" {
			reqID = uuid.NewString()

			r.Header.Set(RequestIDHeader, reqID)
		}

		w.Header().Set(RequestIDHeader, reqID)

		lrw := &loggingResponseWriter{ResponseWriter: w}

		next.ServeHTTP(lrw, r)
		dur := time.Since(start)

		entry := loggerEntryBase.WithFields(logrus.Fields{
			"request_id":            reqID,
			"method":                r.Method,
			"path":                  r.URL.Path,
			"query":                 r.URL.RawQuery,
			"status":                lrw.status,
			"bytes":                 lrw.bytes,
			"duration_ms":           dur.Milliseconds(),
			"remote_ip":             realIP(r),
			"user_agent":            r.UserAgent(),
			"request_content_type":  r.Header.Get("Content-Type"),
			"response_content_type": lrw.Header().Get("Content-Type"),
		})

		if lrw.status == 0 {
			lrw.status = http.StatusOK
		}

		switch {
		case lrw.status >= 500:
			entry.Error("http request finished")
		case lrw.status >= 400:
			entry.Warn("http request finished")
		default:
			entry.Info("http request finished")
		}
	})
}

func realIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")

		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	if xrip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xrip != "" {
		return xrip
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}

	return r.RemoteAddr
}
