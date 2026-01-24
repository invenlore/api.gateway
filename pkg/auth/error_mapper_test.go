package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/invenlore/api.gateway/pkg/logger"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestWriteErrorResponseBasic(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(logger.RequestIDHeader, "req-123")

	st := status.New(codes.NotFound, "not found")
	WriteErrorResponse(recorder, request, st)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", recorder.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	statusObj, ok := payload["status"].(map[string]any)
	if !ok {
		t.Fatalf("expected status object in response")
	}

	if statusObj["code"] != codes.NotFound.String() {
		t.Fatalf("expected code %s, got %v", codes.NotFound.String(), statusObj["code"])
	}

	if statusObj["message"] != "not found" {
		t.Fatalf("expected message 'not found', got %v", statusObj["message"])
	}

	if payload["request_id"] != "req-123" {
		t.Fatalf("expected request_id req-123, got %v", payload["request_id"])
	}
}

func TestWriteErrorResponseWithDetails(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set(logger.RequestIDHeader, "req-456")

	st := status.New(codes.InvalidArgument, "invalid input")
	withDetails, err := st.WithDetails(&errdetails.BadRequest{
		FieldViolations: []*errdetails.BadRequest_FieldViolation{
			{Field: "email", Description: "email is required"},
		},
	})
	if err != nil {
		t.Fatalf("failed to attach details: %v", err)
	}

	WriteErrorResponse(recorder, request, withDetails)

	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	statusObj := payload["status"].(map[string]any)
	if statusObj["code"] != codes.InvalidArgument.String() {
		t.Fatalf("expected code %s, got %v", codes.InvalidArgument.String(), statusObj["code"])
	}

	details, ok := statusObj["details"].([]any)
	if !ok || len(details) == 0 {
		t.Fatalf("expected details to be present")
	}

	firstDetail := details[0].(map[string]any)
	if firstDetail["@type"] != "google.rpc.BadRequest" {
		t.Fatalf("expected BadRequest detail type, got %v", firstDetail["@type"])
	}
}

func TestWriteErrorResponseTable(t *testing.T) {
	testCases := []struct {
		name           string
		code           codes.Code
		message        string
		detail         any
		expectedType   string
		expectHTTPCode int
	}{
		{
			name:           "error info",
			code:           codes.PermissionDenied,
			message:        "denied",
			detail:         &errdetails.ErrorInfo{Reason: "AUTHZ", Domain: "invenlore"},
			expectedType:   "google.rpc.ErrorInfo",
			expectHTTPCode: http.StatusForbidden,
		},
		{
			name:           "retry info",
			code:           codes.Unavailable,
			message:        "unavailable",
			detail:         &errdetails.RetryInfo{RetryDelay: durationpb.New(500 * time.Millisecond)},
			expectedType:   "google.rpc.RetryInfo",
			expectHTTPCode: http.StatusServiceUnavailable,
		},
		{
			name:           "unknown detail",
			code:           codes.Aborted,
			message:        "aborted",
			detail:         &errdetails.RequestInfo{RequestId: "req-unknown"},
			expectedType:   "*errdetails.RequestInfo",
			expectHTTPCode: http.StatusConflict,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set(logger.RequestIDHeader, "req-789")

			st := status.New(tc.code, tc.message)
			var withDetails *status.Status
			var err error

			switch detail := tc.detail.(type) {
			case *errdetails.ErrorInfo:
				withDetails, err = st.WithDetails(detail)
			case *errdetails.RetryInfo:
				withDetails, err = st.WithDetails(detail)
			case *errdetails.RequestInfo:
				withDetails, err = st.WithDetails(detail)
			default:
				t.Fatalf("unsupported detail type: %T", tc.detail)
			}

			if err != nil {
				t.Fatalf("failed to attach details: %v", err)
			}

			WriteErrorResponse(recorder, request, withDetails)

			if recorder.Code != tc.expectHTTPCode {
				t.Fatalf("expected http %d, got %d", tc.expectHTTPCode, recorder.Code)
			}

			var payload map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			statusObj := payload["status"].(map[string]any)
			details := statusObj["details"].([]any)
			if len(details) == 0 {
				t.Fatalf("expected details to be present")
			}

			firstDetail := details[0].(map[string]any)
			if firstDetail["@type"] != tc.expectedType {
				t.Fatalf("expected detail type %s, got %v", tc.expectedType, firstDetail["@type"])
			}
		})
	}
}
