package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	HeaderAuthorization = "Authorization"
	HeaderUserID        = "X-User-Id"
	HeaderUserRoles     = "X-Roles"
	HeaderUserPerms     = "X-Perms-Global"
	HeaderUserScopes    = "X-Scopes"
	HeaderIdempotency   = "X-Idempotency-Key"
)

type Claims struct {
	Roles        []string `json:"roles"`
	PermsGlobal  []string `json:"perms_global"`
	PermsProject []string `json:"perms_project"`
	Scopes       []string `json:"scopes"`
	jwt.RegisteredClaims
}

type JWKSFetcher interface {
	Get(ctx context.Context) ([]byte, error)
}

type Middleware struct {
	logger       *logrus.Entry
	jwksFetcher  JWKSFetcher
	allowedSkew  time.Duration
	publicPaths  map[string]struct{}
	requireToken bool
}

type MiddlewareConfig struct {
	JWKSFetcher  JWKSFetcher
	AllowedSkew  time.Duration
	PublicPaths  []string
	RequireToken bool
}

func NewMiddleware(cfg MiddlewareConfig) *Middleware {
	paths := map[string]struct{}{}
	for _, path := range cfg.PublicPaths {
		paths[path] = struct{}{}
	}

	return &Middleware{
		logger:       logrus.WithField("scope", "auth.middleware"),
		jwksFetcher:  cfg.JWKSFetcher,
		allowedSkew:  cfg.AllowedSkew,
		publicPaths:  paths,
		requireToken: cfg.RequireToken,
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := m.publicPaths[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		claims, source, err := m.authenticate(ctx, r)
		if err != nil {
			m.writeAuthError(w, r, err)
			return
		}

		if source == AuthSourceCookie {
			r = r.WithContext(WithAuthSource(r.Context(), source))
		}

		if claims != nil {
			if claims.Subject != "" {
				r.Header.Set(HeaderUserID, claims.Subject)
			}

			if len(claims.Roles) > 0 {
				r.Header.Set(HeaderUserRoles, strings.Join(claims.Roles, ","))
			}

			if len(claims.PermsGlobal) > 0 {
				r.Header.Set(HeaderUserPerms, strings.Join(claims.PermsGlobal, ","))
			}

			if len(claims.Scopes) > 0 {
				r.Header.Set(HeaderUserScopes, strings.Join(claims.Scopes, ","))
			}
		}

		if !m.isAuthorizedForPath(r.URL.Path, claims) {
			st := status.New(codes.PermissionDenied, "forbidden")

			WriteErrorResponse(w, r, st)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) isAuthorizedForPath(path string, claims *Claims) bool {
	if isSwaggerPath(path) {
		return hasGlobalPermission(claims, "gateway.swagger.read")
	}

	if !strings.HasPrefix(path, "/v1/admin/") {
		return true
	}

	return hasGlobalPermission(claims, "identity.*")
}

func hasGlobalPermission(claims *Claims, permission string) bool {
	if claims == nil {
		return false
	}

	for _, perm := range claims.PermsGlobal {
		if perm == permission {
			return true
		}

		if perm == "identity.all" {
			return true
		}

		if strings.HasSuffix(permission, ".*") {
			continue
		}

		if strings.HasSuffix(perm, ".*") {
			if strings.HasPrefix(permission, strings.TrimSuffix(perm, ".*")) {
				return true
			}
		}
	}

	return false
}

func isSwaggerPath(path string) bool {
	if path == "/api.swagger.json" || path == "/swagger" {
		return true
	}

	return strings.HasPrefix(path, "/swagger/")
}

func (m *Middleware) authenticate(ctx context.Context, r *http.Request) (*Claims, AuthSource, error) {
	rawToken := strings.TrimSpace(r.Header.Get(HeaderAuthorization))
	if rawToken == "" {
		if cookieToken, ok := readBearerFromCookie(r); ok {
			claims, err := m.parseToken(ctx, cookieToken)
			if err != nil {
				return nil, "", err
			}

			r.Header.Set(HeaderAuthorization, "Bearer "+cookieToken)
			return claims, AuthSourceCookie, nil
		}

		if m.requireToken {
			return nil, "", errTokenMissing
		}

		return nil, "", nil
	}

	parts := strings.SplitN(rawToken, " ", 2)

	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, "", errTokenInvalid
	}

	claims, err := m.parseToken(ctx, parts[1])
	return claims, "", err
}

func (m *Middleware) parseToken(ctx context.Context, token string) (*Claims, error) {
	parser := jwt.NewParser(jwt.WithLeeway(m.allowedSkew))
	claims := &Claims{}

	_, err := parser.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return m.resolveKey(ctx, token)
	})
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func readBearerFromCookie(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}

	cookie, err := r.Cookie(CookieAccessToken)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return "", false
	}

	return strings.TrimSpace(cookie.Value), true
}

func (m *Middleware) resolveKey(ctx context.Context, token *jwt.Token) (interface{}, error) {
	if token == nil || token.Method == nil {
		return nil, errTokenInvalid
	}

	encoded, err := m.jwksFetcher.Get(ctx)
	if err != nil {
		return nil, err
	}

	decoded, err := decodeJWKSPayload(encoded)
	if err != nil {
		return nil, err
	}

	set, err := ParseJWKS(decoded)
	if err != nil {
		return nil, err
	}

	kid, _ := token.Header["kid"].(string)

	key, err := set.FindKey(kid)
	if err != nil {
		return nil, err
	}

	return key.ToPublicKey()
}

func (m *Middleware) writeAuthError(w http.ResponseWriter, r *http.Request, err error) {
	message := "unauthorized"

	if errors.Is(err, errTokenMissing) {
		message = "authorization token missing"
	} else if errors.Is(err, errTokenInvalid) {
		message = "invalid authorization token"
	}

	if shouldRedirectToLogin(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	st := status.New(codes.Unauthenticated, message)
	WriteErrorResponse(w, r, st)
}

func shouldRedirectToLogin(r *http.Request) bool {
	if r == nil {
		return false
	}

	if r.Method != http.MethodGet {
		return false
	}

	if !isSwaggerPath(r.URL.Path) {
		return false
	}

	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "text/html") || accept == ""
}

var (
	errTokenMissing = errors.New("token missing")
	errTokenInvalid = errors.New("token invalid")
)

func decodeJWKSPayload(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("jwks payload is empty")
	}

	trimmed := strings.TrimSpace(string(encoded))
	if strings.HasPrefix(trimmed, "{") {
		return encoded, nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}
