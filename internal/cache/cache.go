package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type Cache struct {
	client *redis.Client
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
}

func NewCache(config Config) (*Cache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, err
	}

	return &Cache{client: client}, nil
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	return c.client.Get(ctx, key).Result()
}

func (c *Cache) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	return c.client.Set(ctx, key, value, expiration).Err()
}

// Add Set operations
func (c *Cache) SAdd(ctx context.Context, key string, members ...interface{}) error {
	return c.client.SAdd(ctx, key, members...).Err()
}

func (c *Cache) SMembers(ctx context.Context, key string) ([]string, error) {
	return c.client.SMembers(ctx, key).Result()
}

func (c *Cache) SRem(ctx context.Context, key string, members ...interface{}) error {
	return c.client.SRem(ctx, key, members...).Err()
}

func (c *Cache) GetClient() *redis.Client {
	return c.client
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, key).Err()
}

func (c *Cache) Del(ctx context.Context, keys ...string) error {
	return c.client.Del(ctx, keys...).Err()
}

func (c *Cache) Keys(ctx context.Context, pattern string) ([]string, error) {
	return c.client.Keys(ctx, pattern).Result()
}
