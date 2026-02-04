package auth

import (
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
