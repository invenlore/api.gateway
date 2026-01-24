package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/logger"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestErrorMapperWithServeMux(t *testing.T) {
	mapper := &ErrorMapper{}
	mux := runtime.NewServeMux(runtime.WithErrorHandler(mapper.Handler))

	mux.HandlePath("GET", "/test", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		err := status.New(codes.InvalidArgument, "invalid input")
		withDetails, attachErr := err.WithDetails(&errdetails.BadRequest{
			FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: "name", Description: "required"}},
		})
		if attachErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		runtime.HTTPError(r.Context(), mux, &runtime.JSONPb{}, w, r, withDetails.Err())
	})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Header.Set(logger.RequestIDHeader, "req-int-1")

	mux.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	statusObj := payload["status"].(map[string]any)
	if statusObj["code"] != codes.InvalidArgument.String() {
		t.Fatalf("expected code %s, got %v", codes.InvalidArgument.String(), statusObj["code"])
	}

	if payload["request_id"] != "req-int-1" {
		t.Fatalf("expected request_id req-int-1, got %v", payload["request_id"])
	}
}
