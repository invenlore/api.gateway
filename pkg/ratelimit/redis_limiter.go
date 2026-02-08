package ratelimit

import (
	"context"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

type RedisLimiter struct {
	limiter *redis_rate.Limiter
}

func NewRedisLimiter(client *redis.Client) *RedisLimiter {
	if client == nil {
		return nil
	}

	return &RedisLimiter{limiter: redis_rate.NewLimiter(client)}
}

func (r *RedisLimiter) Allow(ctx context.Context, key string, limit Limit) (Decision, error) {
	if r == nil || r.limiter == nil {
		return Decision{Allowed: true}, nil
	}

	if limit.RPS <= 0 {
		return Decision{Allowed: true}, nil
	}

	period := limit.Period
	if period <= 0 {
		period = time.Second
	}

	res, err := r.limiter.Allow(ctx, key, redis_rate.Limit{
		Rate:   limit.RPS,
		Burst:  limit.Burst,
		Period: period,
	})

	if err != nil {
		return Decision{}, err
	}

	return Decision{
		Allowed:    res.Allowed > 0,
		Remaining:  res.Remaining,
		RetryAfter: res.RetryAfter,
		ResetAt:    time.Now().Add(res.ResetAfter),
	}, nil
}
