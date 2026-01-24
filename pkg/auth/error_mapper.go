package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/invenlore/api.gateway/pkg/logger"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
)

type ErrorMapper struct {
	Logger *logrus.Entry
}

func (m *ErrorMapper) Handler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, r *http.Request, err error) {
	st := status.Convert(err)
	WriteErrorResponse(w, r, st)
}

type errorResponse struct {
	Status    errorStatus `json:"status"`
	RequestID string      `json:"request_id,omitempty"`
}

type errorStatus struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Details []interface{} `json:"details,omitempty"`
}

func WriteErrorResponse(w http.ResponseWriter, r *http.Request, st *status.Status) {
	statusCode := runtime.HTTPStatusFromCode(st.Code())
	requestID := r.Header.Get(logger.RequestIDHeader)

	response := errorResponse{
		Status: errorStatus{
			Code:    st.Code().String(),
			Message: st.Message(),
			Details: mapDetails(st.Details()),
		},
		RequestID: requestID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

func mapDetails(details []interface{}) []interface{} {
	if len(details) == 0 {
		return nil
	}

	mapped := make([]interface{}, 0, len(details))
	for _, detail := range details {
		switch d := detail.(type) {
		case *errdetails.BadRequest:
			mapped = append(mapped, map[string]interface{}{
				"@type":            "google.rpc.BadRequest",
				"field_violations": d.FieldViolations,
			})
		case *errdetails.ErrorInfo:
			mapped = append(mapped, map[string]interface{}{
				"@type":    "google.rpc.ErrorInfo",
				"reason":   d.Reason,
				"domain":   d.Domain,
				"metadata": d.Metadata,
			})
		case *errdetails.RetryInfo:
			mapped = append(mapped, map[string]interface{}{
				"@type":       "google.rpc.RetryInfo",
				"retry_delay": d.RetryDelay,
			})
		default:
			mapped = append(mapped, map[string]interface{}{
				"@type": fmt.Sprintf("%T", detail),
				"value": detail,
			})
		}
	}

	return mapped
}
