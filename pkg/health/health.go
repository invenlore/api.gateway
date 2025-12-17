package health

import (
	"context"
	"net/http"
	"time"

	"github.com/alexliesenfeld/health"
	"github.com/sirupsen/logrus"
)

func LoggerHealthMiddleware() health.Middleware {
	return func(next health.MiddlewareFunc) health.MiddlewareFunc {
		return func(r *http.Request) health.CheckerResult {
			now := time.Now()
			result := next(r)

			logrus.Infof("processed health check request in %f seconds (result: %s)",
				time.Since(now).Seconds(), result.Status)

			return result
		}
	}
}

func LoggerHealthInterceptor() health.Interceptor {
	return func(next health.InterceptorFunc) health.InterceptorFunc {
		return func(ctx context.Context, name string, state health.CheckState) health.CheckState {
			now := time.Now()
			result := next(ctx, name, state)

			logrus.Infof("executed health check function of component %s in %f seconds (result: %s)",
				name, time.Since(now).Seconds(), result.Status)

			return result
		}
	}
}

func GetHealthHandler() http.Handler {
	checker := health.NewChecker(
		health.WithCacheDuration(1*time.Second),
		health.WithTimeout(10*time.Second),
		health.WithInterceptors(LoggerHealthInterceptor()),
	)

	return health.NewHandler(
		checker,
		health.WithMiddleware(LoggerHealthMiddleware()),
		health.WithStatusCodeDown(503),
	)
}
