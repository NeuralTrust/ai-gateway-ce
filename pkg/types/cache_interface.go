package types

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
)

// Cache defines the caching interface
type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	Client() *redis.Client
	CreateTTLMap(name string, ttl time.Duration) *TTLMap
	GetTTLMap(name string) *TTLMap
}
