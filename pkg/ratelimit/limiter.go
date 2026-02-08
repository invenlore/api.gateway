package ratelimit

import (
	"context"
	"time"
)

type Limit struct {
	RPS    int
	Burst  int
	Period time.Duration
}

type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
	ResetAt    time.Time
}

type Limiter interface {
	Allow(ctx context.Context, key string, limit Limit) (Decision, error)
}
