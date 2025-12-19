package utils

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"

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
		w.Header().Set("Content-Type", "application/json")
		w.Write(ch.swaggerJSON)

		return
	}

	if r.URL.Path == "/swagger" {
		http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)

		return
	}

	if strings.HasPrefix(r.URL.Path, "/api/") {
		ch.mux.ServeHTTP(w, r)

		return
	}

	if ch.swaggerErr == nil && ch.swaggerHandler != nil {
		ch.swaggerHandler.ServeHTTP(w, r)

		return
	}

	http.NotFound(w, r)
}

func getSwaggerUIHandler() (http.Handler, error) {
	swaggerSubFS, err := third_party.GetSwaggerUISubFS()
	if err != nil {
		return nil, fmt.Errorf("couldn't get swagger sub filesystem: %v", err)
	}

	mime.AddExtensionType(".svg", "image/svg+xml")

	return http.StripPrefix("/swagger/", http.FileServer(http.FS(swaggerSubFS))), nil
}

func NewCombinedHandler(ctx context.Context, mux *runtime.ServeMux) (*CombinedHandler, error) {
	factory := &CombinedHandler{
		mux:         mux,
		swaggerJSON: third_party.GetSwaggerJSON(),
	}

	factory.swaggerHandler, factory.swaggerErr = getSwaggerUIHandler()
	if factory.swaggerErr != nil {
		logrus.Errorf("couldn't get swagger handler: %v", factory.swaggerErr)
	}

	return factory, nil
}
