package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"ai-gateway-ce/pkg/common"
)

// Cache implements the common.Cache interface
type Cache struct {
	client     *redis.Client
	db         *gorm.DB
	localCache sync.Map
	ttlMaps    sync.Map
	ttl        time.Duration
}

func NewCache(config common.CacheConfig, db *gorm.DB) (*Cache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
	})

	return &Cache{
		client:     client,
		db:         db,
		localCache: sync.Map{},
		ttlMaps:    sync.Map{},
		ttl:        5 * time.Minute,
	}, nil
}

func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	if value, ok := c.localCache.Load(key); ok {
		return value.(string), nil
	}
	return c.client.Get(ctx, key).Result()
}

func (c *Cache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return err
	}
	c.localCache.Store(key, value)
	return nil
}

func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return err
	}
	c.localCache.Delete(key)
	return nil
}

func (c *Cache) Client() *redis.Client {
	return c.client
}

func (c *Cache) CreateTTLMap(name string, ttl time.Duration) *common.TTLMap {
	ttlMap := common.NewTTLMap(ttl)
	c.ttlMaps.Store(name, ttlMap)
	return ttlMap
}

func (c *Cache) GetTTLMap(name string) *common.TTLMap {
	if value, ok := c.ttlMaps.Load(name); ok {
		return value.(*common.TTLMap)
	}
	return nil
}
