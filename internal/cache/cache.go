package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type Cache struct {
	client     *redis.Client
	localCache *sync.Map
	ttl        time.Duration
}

type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
	PoolSize int
	LocalTTL time.Duration
}

func NewCache(config Config) (*Cache, error) {
	if config.PoolSize == 0 {
		config.PoolSize = 100 // Default pool size
	}
	if config.LocalTTL == 0 {
		config.LocalTTL = 5 * time.Second // Default local cache TTL
	}

	client := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password:     config.Password,
		DB:           config.DB,
		PoolSize:     config.PoolSize,
		MinIdleConns: config.PoolSize / 2,
		MaxConnAge:   30 * time.Minute,
		IdleTimeout:  5 * time.Minute,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &Cache{
		client:     client,
		localCache: &sync.Map{},
		ttl:        config.LocalTTL,
	}, nil
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	// Try local cache first
	if entry, ok := c.localCache.Load(key); ok {
		cacheEntry := entry.(cacheEntry)
		if time.Now().Before(cacheEntry.expiresAt) {
			return cacheEntry.value, nil
		}
		c.localCache.Delete(key)
	}

	// Try Redis
	value, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("key not found: %s", key)
		}
		return "", fmt.Errorf("redis error: %w", err)
	}

	// Update local cache
	c.localCache.Store(key, cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	})

	return value, nil
}

func (c *Cache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	// Set in Redis first
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return fmt.Errorf("redis error: %w", err)
	}

	// Update local cache
	c.localCache.Store(key, cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	})

	return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	// Delete from Redis first
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis error: %w", err)
	}

	// Delete from local cache
	c.localCache.Delete(key)

	return nil
}

func (c *Cache) MGet(ctx context.Context, keys ...string) ([]string, error) {
	// Try local cache first
	results := make([]string, len(keys))
	missingKeys := make([]string, 0)
	missingIndexes := make([]int, 0)

	for i, key := range keys {
		if entry, ok := c.localCache.Load(key); ok {
			cacheEntry := entry.(cacheEntry)
			if time.Now().Before(cacheEntry.expiresAt) {
				results[i] = cacheEntry.value
				continue
			}
			c.localCache.Delete(key)
		}
		missingKeys = append(missingKeys, key)
		missingIndexes = append(missingIndexes, i)
	}

	// If all found in local cache
	if len(missingKeys) == 0 {
		return results, nil
	}

	// Get missing keys from Redis
	values, err := c.client.MGet(ctx, missingKeys...).Result()
	if err != nil {
		return nil, fmt.Errorf("redis error: %w", err)
	}

	// Update results and local cache
	for i, value := range values {
		if value != nil {
			strValue := value.(string)
			results[missingIndexes[i]] = strValue
			c.localCache.Store(missingKeys[i], cacheEntry{
				value:     strValue,
				expiresAt: time.Now().Add(c.ttl),
			})
		}
	}

	return results, nil
}

func (c *Cache) MSet(ctx context.Context, pairs map[string]string, expiration time.Duration) error {
	// Convert to Redis format
	args := make([]interface{}, 0, len(pairs)*2)
	for k, v := range pairs {
		args = append(args, k, v)
	}

	// Set in Redis
	pipe := c.client.Pipeline()
	pipe.MSet(ctx, args...)
	for k := range pairs {
		if expiration > 0 {
			pipe.Expire(ctx, k, expiration)
		}
	}
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis error: %w", err)
	}

	// Update local cache
	for k, v := range pairs {
		c.localCache.Store(k, cacheEntry{
			value:     v,
			expiresAt: time.Now().Add(c.ttl),
		})
	}

	return nil
}

func (c *Cache) Close() error {
	return c.client.Close()
}

func (c *Cache) Client() *redis.Client {
	return c.client
}

// Helper function to marshal and cache JSON
func (c *Cache) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}
	return c.Set(ctx, key, string(data), expiration)
}

// Helper function to get and unmarshal JSON
func (c *Cache) GetJSON(ctx context.Context, key string, value interface{}) error {
	data, err := c.Get(ctx, key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), value)
}
