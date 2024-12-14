package database

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// Repository handles all database operations
type Repository struct {
	db     *gorm.DB
	logger logrus.FieldLogger
	cache  *cache.Cache
}

func NewRepository(db *gorm.DB, logger logrus.FieldLogger, cache *cache.Cache) *Repository {
	return &Repository{
		db:     db,
		logger: logger,
		cache:  cache,
	}
}

// IsValidAPIKey checks if the provided API key is valid for the given gateway
func (r *Repository) IsValidAPIKey(gatewayID, apiKey string) bool {
	var count int64

	// Check in database first
	result := r.db.Model(&models.APIKey{}).
		Where("gateway_id = ? AND key = ? AND active = true AND (expires_at IS NULL OR expires_at > NOW())",
			gatewayID, apiKey).
		Count(&count)

	if result.Error != nil {
		r.logger.Error(context.Background(), "Failed to check API key validity", "error", result.Error)
		return false
	}

	// If key is valid, cache it
	if count > 0 {
		cacheKey := fmt.Sprintf("apikey:%s:%s", gatewayID, apiKey)
		value, err := json.Marshal(true)
		if err != nil {
			r.logger.Warn(context.Background(), "Failed to marshal cache value", "error", err)
		} else {
			if err := r.cache.Set(context.Background(), cacheKey, string(value), 5*time.Minute); err != nil {
				r.logger.Warn(context.Background(), "Failed to cache valid API key", "error", err)
			}
		}
	}

	return count > 0
}

// IsValidAPIKeyFast checks cache first, then database
func (r *Repository) IsValidAPIKeyFast(gatewayID, apiKey string) bool {
	cacheKey := fmt.Sprintf("apikey:%s:%s", gatewayID, apiKey)

	// Try cache first
	value, err := r.cache.Get(context.Background(), cacheKey)
	if err == nil {
		var isValid bool
		if err := json.Unmarshal([]byte(value), &isValid); err == nil && isValid {
			return true
		}
	}

	// If not in cache or invalid, check database
	return r.IsValidAPIKey(gatewayID, apiKey)
}

// Gateway operations
func (r *Repository) CreateGateway(ctx context.Context, gateway *models.Gateway) error {
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return r.db.Create(gateway).Error
}

func (r *Repository) GetGateway(ctx context.Context, id string) (*models.Gateway, error) {
	var gateway models.Gateway
	if err := r.db.First(&gateway, "id = ?", id).Error; err != nil {
		return nil, err
	}
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return &gateway, nil
}

func (r *Repository) GetGatewayBySubdomain(ctx context.Context, subdomain string) (*models.Gateway, error) {
	var gateway models.Gateway
	err := r.db.Model(&models.Gateway{}).Where("subdomain = ?", subdomain).Take(&gateway).Error
	if err != nil {
		return nil, err
	}

	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}

	return &gateway, nil
}

func (r *Repository) ListGateways(ctx context.Context, offset, limit int) ([]models.Gateway, error) {
	var gateways []models.Gateway
	err := r.db.Model(&models.Gateway{}).
		Order("created_at desc").
		Limit(limit).
		Offset(offset).
		Find(&gateways).Error

	for i := range gateways {
		if gateways[i].RequiredPlugins == nil {
			gateways[i].RequiredPlugins = []types.PluginConfig{}
		}
	}

	return gateways, err
}

func (r *Repository) UpdateGateway(ctx context.Context, gateway *models.Gateway) error {
	if gateway.RequiredPlugins == nil {
		gateway.RequiredPlugins = []types.PluginConfig{}
	}
	return r.db.Save(gateway).Error
}

func (r *Repository) DeleteGateway(ctx context.Context, id string) error {
	result := r.db.Delete(&models.Gateway{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("gateway not found")
	}
	return nil
}

// Forwarding Rule operations
func (r *Repository) CreateRule(ctx context.Context, rule *models.ForwardingRule) error {
	return r.db.Create(rule).Error
}

func (r *Repository) GetRule(ctx context.Context, id string, gatewayID string) (*models.ForwardingRule, error) {
	var rule models.ForwardingRule
	err := r.db.Where("id = ? AND gateway_id = ?", id, gatewayID).First(&rule).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *Repository) ListRules(ctx context.Context, gatewayID string) ([]models.ForwardingRule, error) {
	var rules []models.ForwardingRule
	err := r.db.Where("gateway_id = ?", gatewayID).Find(&rules).Error
	return rules, err
}

func (r *Repository) UpdateRule(ctx context.Context, rule *models.ForwardingRule) error {
	result := r.db.Save(rule)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

func (r *Repository) DeleteRule(ctx context.Context, id, gatewayID string) error {
	result := r.db.Where("id = ? AND gateway_id = ?", id, gatewayID).Delete(&models.ForwardingRule{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// API Key operations
func (r *Repository) CreateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	if apiKey.GatewayID == "" {
		return fmt.Errorf("gateway_id is required")
	}
	if apiKey.Name == "" {
		return fmt.Errorf("name is required")
	}
	if apiKey.Key == "" {
		return fmt.Errorf("key is required")
	}

	now := time.Now()
	if apiKey.CreatedAt.IsZero() {
		apiKey.CreatedAt = now
	}
	if apiKey.UpdatedAt.IsZero() {
		apiKey.UpdatedAt = now
	}

	if !apiKey.Active {
		apiKey.Active = true
	}

	result := r.db.Create(apiKey)
	if result.Error != nil {
		return fmt.Errorf("failed to create API key: %w", result.Error)
	}

	return nil
}

func (r *Repository) GetAPIKey(ctx context.Context, id string) (*models.APIKey, error) {
	var apiKey models.APIKey
	err := r.db.Where("id = ?", id).First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

func (r *Repository) ListAPIKeys(ctx context.Context, gatewayID string) ([]models.APIKey, error) {
	var apiKeys []models.APIKey
	err := r.db.Where("gateway_id = ?", gatewayID).Find(&apiKeys).Error
	return apiKeys, err
}

func (r *Repository) UpdateAPIKey(ctx context.Context, apiKey *models.APIKey) error {
	result := r.db.Save(apiKey)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *Repository) DeleteAPIKey(ctx context.Context, id, gatewayID string) error {
	result := r.db.Where("id = ? AND gateway_id = ?", id, gatewayID).Delete(&models.APIKey{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("api key not found")
	}
	return nil
}

func (r *Repository) SubdomainExists(ctx context.Context, subdomain string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Gateway{}).
		Where("subdomain = ?", subdomain).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check subdomain existence: %w", err)
	}
	return count > 0, nil
}

func (r *Repository) IsSubdomainAvailable(subdomain string) (bool, error) {
	var count int64
	err := r.db.Model(&models.Gateway{}).Where("subdomain = ?", subdomain).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check subdomain: %w", err)
	}
	return count == 0, nil
}

func (r *Repository) ValidateAPIKey(ctx context.Context, gatewayID string, apiKey string) (bool, error) {
	var exists int64
	err := r.db.Model(&models.APIKey{}).
		Where("gateway_id = ? AND key = ? AND (expires_at IS NULL OR expires_at > ?)",
			gatewayID, apiKey, time.Now()).
		Count(&exists).Error

	if err != nil {
		return false, err
	}

	return exists > 0, nil
}
