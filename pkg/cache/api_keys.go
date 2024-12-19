package cache

import (
	"ai-gateway-ce/pkg/models"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

func (c *Cache) GetAPIKeys(gatewayID string) ([]models.APIKey, error) {
	key := fmt.Sprintf("apikeys:%s", gatewayID)
	data, err := c.Client().Get(context.Background(), key).Result()
	if err != nil {
		if err == redis.Nil {
			return []models.APIKey{}, nil
		}
		return nil, err
	}

	var keys []models.APIKey
	if err := json.Unmarshal([]byte(data), &keys); err != nil {
		return nil, err
	}

	return keys, nil
}

func (c *Cache) ValidateAPIKey(gatewayID, apiKey string) bool {
	key, err := c.GetAPIKey(gatewayID, apiKey)
	if err != nil {
		return false
	}

	if key == nil {
		return false
	}

	now := time.Now()
	return key.Active && (key.ExpiresAt.IsZero() || key.ExpiresAt.After(now))
}

func (c *Cache) GetAPIKey(gatewayID, apiKey string) (*models.APIKey, error) {
	// Get all API keys for the gateway
	keys, err := c.GetAPIKeys(gatewayID)
	if err != nil {
		return nil, err
	}

	// Find the matching key
	for _, key := range keys {
		if key.Key == apiKey {
			return &key, nil
		}
	}

	return nil, nil
}

func (c *Cache) SaveAPIKey(ctx context.Context, key *models.APIKey) error {
	// Get existing keys
	keys, err := c.GetAPIKeys(key.GatewayID)
	if err != nil {
		return err
	}

	// Add new key
	keys = append(keys, *key)

	// Save back to cache
	data, err := json.Marshal(keys)
	if err != nil {
		return err
	}

	cacheKey := fmt.Sprintf("apikeys:%s", key.GatewayID)
	return c.Client().Set(ctx, cacheKey, string(data), 0).Err()
}
