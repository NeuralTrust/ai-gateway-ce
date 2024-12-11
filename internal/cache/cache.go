package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type Cache struct {
	client     *redis.Client
	db         *gorm.DB
	localCache sync.Map
	ttl        time.Duration
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// NewCache creates a new cache instance with Redis and local memory caching
func NewCache(config Config, db *gorm.DB) (*Cache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Cache{
		client:     client,
		db:         db,
		localCache: sync.Map{},
		ttl:        5 * time.Minute,
	}, nil
}

// Get retrieves a value from cache, trying local cache first
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	// Try local cache first
	if value, ok := c.localCache.Load(key); ok {
		return value.(string), nil
	}

	// Try Redis
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		return "", err
	}

	// Store in local cache
	c.localCache.Store(key, val)
	return val, nil
}

// Set stores a value in both Redis and local cache
func (c *Cache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	// Store in Redis
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}

	// Store in local cache
	c.localCache.Store(key, value)
	return nil
}

// Delete removes a value from both Redis and local cache
func (c *Cache) Delete(ctx context.Context, key string) error {
	// Delete from Redis
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return err
	}

	// Delete from local cache
	c.localCache.Delete(key)
	return nil
}

// Client returns the Redis client for plugin usage
func (c *Cache) Client() *redis.Client {
	return c.client
}
