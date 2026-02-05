package auth

import "context"

const (
	CookieAccessToken  = "access_token"
	CookieRefreshToken = "refresh_token"
	CookieCSRFToken    = "csrf_token"
)

const HeaderCSRFTOKEN = "X-CSRF-Token"

type AuthSource string

const (
	AuthSourceCookie AuthSource = "cookie"
)

type authSourceKey struct{}

func WithAuthSource(ctx context.Context, source AuthSource) context.Context {
	return context.WithValue(ctx, authSourceKey{}, source)
}

func AuthSourceFromContext(ctx context.Context) (AuthSource, bool) {
	value, ok := ctx.Value(authSourceKey{}).(AuthSource)

	return value, ok
}
