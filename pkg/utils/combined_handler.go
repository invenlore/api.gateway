package utils

import (
	"bytes"
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	third_party "github.com/invenlore/proto"
	"github.com/sirupsen/logrus"
)

type CombinedHandler struct {
	mux            *runtime.ServeMux
	swaggerJSON    []byte
	swaggerHandler http.Handler
	swaggerErr     error
}

func (ch *CombinedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api.swagger.json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		http.ServeContent(w, r, "api.swagger.json", time.Time{}, bytes.NewReader(ch.swaggerJSON))

		return
	}

	if r.URL.Path == "/swagger" {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)

		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		http.Redirect(w, r, "/v1/", http.StatusMovedPermanently)

		return
	}

	if isVersionedAPIPath(r.URL.Path) {
		ch.mux.ServeHTTP(w, r)

		return
	}

	if ch.swaggerErr == nil && ch.swaggerHandler != nil {
		ch.swaggerHandler.ServeHTTP(w, r)

		return
	}

	http.NotFound(w, r)
}

func isVersionedAPIPath(path string) bool {
	if !strings.HasPrefix(path, "/v") {
		return false
	}

	trimmed := strings.TrimPrefix(path, "/")
	segmentEnd := strings.Index(trimmed, "/")

	if segmentEnd == -1 {
		return false
	}

	segment := trimmed[:segmentEnd]
	if len(segment) < 2 || segment[0] != 'v' {
		return false
	}

	for i := 1; i < len(segment); i++ {
		if segment[i] < '0' || segment[i] > '9' {
			return false
		}
	}

	return true
}

func getSwaggerUIHandler() (http.Handler, error) {
	swaggerSubFS, err := third_party.GetSwaggerUISubFS()
	if err != nil {
		return nil, fmt.Errorf("couldn't get swagger sub filesystem: %v", err)
	}

	mime.AddExtensionType(".svg", "image/svg+xml")

	return http.StripPrefix("/swagger/", http.FileServer(http.FS(swaggerSubFS))), nil
}

func NewCombinedHandler(ctx context.Context, mux *runtime.ServeMux) *CombinedHandler {
	loggerEntry := logrus.WithField("scope", "utils")

	handler := &CombinedHandler{
		mux:         mux,
		swaggerJSON: third_party.GetSwaggerJSON(),
	}

	handler.swaggerHandler, handler.swaggerErr = getSwaggerUIHandler()
	if handler.swaggerErr != nil {
		loggerEntry.Errorf("couldn't get swagger handler: %v", handler.swaggerErr)
	}

	return handler
}
