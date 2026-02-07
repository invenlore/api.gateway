package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	identity_v1 "github.com/invenlore/proto/pkg/identity/v1"
	"github.com/sirupsen/logrus"
)

var (
	errJWKSUnavailable = errors.New("jwks is not available")
)

type JWKSProvider interface {
	GetJWKS(ctx context.Context) (*identity_v1.JWKSet, error)
}

type JWKSCache struct {
	provider  JWKSProvider
	ttl       time.Duration
	logger    *logrus.Entry
	metrics   JWKSCacheMetrics
	mu        sync.RWMutex
	cached    *identity_v1.JWKSet
	expiresAt time.Time
}

type JWKSCacheMetrics interface {
	ObserveJWKSRefresh(success bool)
	SetJWKSCacheAge(age time.Duration)
}

func NewJWKSCache(provider JWKSProvider, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		provider: provider,
		ttl:      ttl,
		logger:   logrus.WithField("scope", "auth.jwks"),
	}
}

func NewJWKSCacheWithMetrics(provider JWKSProvider, ttl time.Duration, metrics JWKSCacheMetrics) *JWKSCache {
	cache := NewJWKSCache(provider, ttl)
	cache.metrics = metrics

	return cache
}

func (c *JWKSCache) Get(ctx context.Context) (*identity_v1.JWKSet, error) {
	c.mu.RLock()
	cached := c.cached
	expiresAt := c.expiresAt
	c.mu.RUnlock()

	if cached != nil && time.Now().Before(expiresAt) {
		if c.metrics != nil {
			c.metrics.SetJWKSCacheAge(time.Since(expiresAt.Add(-c.ttl)))
		}

		return cached, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cached != nil && time.Now().Before(c.expiresAt) {
		if c.metrics != nil {
			c.metrics.SetJWKSCacheAge(time.Since(c.expiresAt.Add(-c.ttl)))
		}

		return c.cached, nil
	}

	jwks, err := c.provider.GetJWKS(ctx)
	if err != nil {
		c.logger.WithError(err).Error("failed to fetch JWKS")
		if c.metrics != nil {
			c.metrics.ObserveJWKSRefresh(false)
		}

		if c.cached != nil {
			return c.cached, nil
		}

		return nil, errJWKSUnavailable
	}

	if jwks == nil || len(jwks.Keys) == 0 {
		if c.metrics != nil {
			c.metrics.ObserveJWKSRefresh(false)
		}

		return nil, errJWKSUnavailable
	}

	c.cached = jwks
	c.expiresAt = time.Now().Add(c.ttl)

	if c.metrics != nil {
		c.metrics.ObserveJWKSRefresh(true)
		c.metrics.SetJWKSCacheAge(0)
	}

	return jwks, nil
}
