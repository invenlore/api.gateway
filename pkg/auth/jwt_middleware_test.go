package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_AdminGuard(t *testing.T) {
	mw := NewMiddleware(MiddlewareConfig{RequireToken: false})

	claims := &Claims{PermsGlobal: []string{"identity.*"}}
	if !mw.isAuthorizedForPath("/v1/admin/users", claims) {
		t.Fatalf("expected admin path to be allowed with identity.*")
	}

	claims = &Claims{PermsGlobal: []string{"wiki.*"}}
	if mw.isAuthorizedForPath("/v1/admin/users", claims) {
		t.Fatalf("expected admin path to be denied without identity permissions")
	}
}

func TestWriteAuthErrorRedirectsSwaggerHtml(t *testing.T) {
	middleware := NewMiddleware(MiddlewareConfig{})

	recorder := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/swagger/", nil)
	req.Header.Set("Accept", "text/html")

	middleware.writeAuthError(recorder, req, errTokenMissing)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected %d, got %d", http.StatusFound, recorder.Code)
	}

	location := recorder.Header().Get("Location")
	if location != "/login" {
		t.Fatalf("expected redirect to /login, got %q", location)
	}
}

func TestWriteAuthErrorKeepsJsonForApi(t *testing.T) {
	middleware := NewMiddleware(MiddlewareConfig{})

	recorder := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users", nil)
	req.Header.Set("Accept", "application/json")

	middleware.writeAuthError(recorder, req, errTokenMissing)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d, got %d", http.StatusUnauthorized, recorder.Code)
	}
}

func TestMiddleware_SwaggerGuard(t *testing.T) {
	mw := NewMiddleware(MiddlewareConfig{RequireToken: false})

	claims := &Claims{PermsGlobal: []string{"gateway.swagger.read"}}
	if !mw.isAuthorizedForPath("/swagger/", claims) {
		t.Fatalf("expected swagger path to be allowed with gateway.swagger.read")
	}

	if !mw.isAuthorizedForPath("/api.swagger.json", claims) {
		t.Fatalf("expected swagger json to be allowed with gateway.swagger.read")
	}

	claims = &Claims{PermsGlobal: []string{"identity.*"}}
	if mw.isAuthorizedForPath("/swagger/", claims) {
		t.Fatalf("expected swagger path to be denied without swagger permission")
	}
}
