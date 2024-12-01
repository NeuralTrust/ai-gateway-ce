package ratelimit

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type RateLimiter struct {
	redis        *redis.Client
	limit        int
	window       time.Duration
	mu           sync.RWMutex
	tenantLimits map[string]int
}

type Config struct {
	DefaultLimit int            `json:"default_limit"`
	Window       time.Duration  `json:"window"`
	TenantLimits map[string]int `json:"tenant_limits"`
}

func NewRateLimiter(redis *redis.Client, config Config) *RateLimiter {
	return &RateLimiter{
		redis:        redis,
		limit:        config.DefaultLimit,
		window:       config.Window,
		tenantLimits: config.TenantLimits,
	}
}

func (r *RateLimiter) Name() string {
	return "rate_limiter"
}

func (r *RateLimiter) Priority() int {
	return 100
}

func (r *RateLimiter) ProcessRequest(ctx context.Context, req *http.Request) error {
	tenantID := req.Header.Get("X-Tenant-ID")
	key := fmt.Sprintf("ratelimit:%s:%s", tenantID, time.Now().Format("2006-01-02-15-04"))

	limit := r.getLimit(tenantID)

	count, err := r.redis.Incr(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}

	// Set expiration on first request
	if count == 1 {
		r.redis.Expire(ctx, key, r.window)
	}

	if count > int64(limit) {
		return fmt.Errorf("rate limit exceeded")
	}

	return nil
}

func (r *RateLimiter) ProcessResponse(ctx context.Context, resp *http.Response) error {
	return nil
}

func (r *RateLimiter) getLimit(tenantID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if limit, ok := r.tenantLimits[tenantID]; ok {
		return limit
	}
	return r.limit
}
