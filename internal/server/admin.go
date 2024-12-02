package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/types"
	"ai-gateway/internal/utils"
)

type AdminServer struct {
	*BaseServer
}

func NewAdminServer(config *Config, cache *cache.Cache, logger *logrus.Logger) *AdminServer {
	return &AdminServer{
		BaseServer: NewBaseServer(config, cache, logger),
	}
}

func (s *AdminServer) setupRoutes() {
	s.setupHealthCheck()

	// Admin API routes
	api := s.router.Group("/api/v1")
	{
		// Tenant management
		tenants := api.Group("/tenants")
		{
			tenants.POST("", s.createTenant)
			tenants.GET("", s.listTenants)
			tenants.GET("/:tenant_id", s.getTenantHandler)
			tenants.PUT("/:tenant_id", s.updateTenant)
			tenants.DELETE("/:tenant_id", s.deleteTenant)

			// API Key management
			apiKeys := tenants.Group("/:tenant_id/api-keys")
			{
				apiKeys.POST("", s.createAPIKey)
				apiKeys.GET("", s.listAPIKeys)
				apiKeys.GET("/:key_id", s.getAPIKeyHandler)
				apiKeys.DELETE("/:key_id", s.revokeAPIKey)
			}

			// Forwarding rules management
			rules := tenants.Group("/:tenant_id/rules")
			{
				rules.POST("", s.createForwardingRule)
				rules.GET("", s.listForwardingRules)
				rules.PUT("/:rule_id", s.updateForwardingRule)
				rules.DELETE("/:rule_id", s.deleteForwardingRule)
			}
		}
	}
}

func (s *AdminServer) Run() error {
	s.setupRoutes()
	return s.router.Run(fmt.Sprintf(":%d", s.config.AdminPort))
}

// Tenant Management
func (s *AdminServer) createTenant(c *gin.Context) {
	var req types.CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenant := &types.Tenant{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Subdomain: req.Subdomain,
		ApiKey:    utils.GenerateApiKey(),
		Status:    "active",
		Tier:      req.Tier,
		CreatedAt: time.Now(),

		UpdatedAt:       time.Now(),
		EnabledPlugins:  req.EnabledPlugins,
		RequiredPlugins: req.RequiredPlugins,
	}

	// Store tenant
	tenantKey := fmt.Sprintf("tenant:%s", tenant.ID)
	tenantJSON, err := json.Marshal(tenant)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	if err := s.cache.Set(c, tenantKey, string(tenantJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to store tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	// Store subdomain mapping
	subdomainKey := fmt.Sprintf("subdomain:%s", tenant.Subdomain)
	if err := s.cache.Set(c, subdomainKey, tenant.ID, 0); err != nil {
		s.logger.WithError(err).Error("Failed to store subdomain mapping")
		s.cache.Del(c, tenantKey)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create tenant"})
		return
	}

	c.JSON(http.StatusCreated, tenant)
}

func (s *AdminServer) listTenants(c *gin.Context) {
	// TODO: Implement pagination
	pattern := "tenant:*"
	keys, err := s.cache.Keys(c, pattern)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get tenant keys")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list tenants"})
		return
	}

	var tenants []types.Tenant
	for _, key := range keys {
		tenantJSON, err := s.cache.Get(c, key)
		if err != nil {
			continue
		}

		var tenant types.Tenant
		if err := json.Unmarshal([]byte(tenantJSON), &tenant); err != nil {
			continue
		}

		// Don't expose API key in list
		tenant.ApiKey = ""
		tenants = append(tenants, tenant)
	}

	c.JSON(http.StatusOK, gin.H{
		"tenants": tenants,
		"count":   len(tenants),
	})
}

func (s *AdminServer) getTenantHandler(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	tenant, err := s.getTenant(c, tenantID)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get tenant"})
		return
	}

	// Don't expose API key
	tenant.ApiKey = ""
	c.JSON(http.StatusOK, tenant)
}

func (s *AdminServer) getTenant(c *gin.Context, id string) (*types.Tenant, error) {
	key := fmt.Sprintf("tenant:%s", id)
	tenantJSON, err := s.cache.Get(c, key)
	if err != nil {
		return nil, err
	}

	var tenant types.Tenant
	if err := json.Unmarshal([]byte(tenantJSON), &tenant); err != nil {
		return nil, err
	}

	return &tenant, nil
}

func (s *AdminServer) updateTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	var req types.UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing tenant
	existingTenant, err := s.getTenant(c, tenantID)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
		return
	}

	// Update fields if provided
	if req.Name != "" {
		existingTenant.Name = req.Name
	}
	if req.Status != "" {
		existingTenant.Status = req.Status
	}
	if req.Tier != "" {
		existingTenant.Tier = req.Tier
	}
	if len(req.EnabledPlugins) > 0 {
		existingTenant.EnabledPlugins = req.EnabledPlugins
	}
	if req.RequiredPlugins != nil {
		existingTenant.RequiredPlugins = req.RequiredPlugins
	}

	existingTenant.UpdatedAt = time.Now()

	// Save updated tenant
	if err := s.saveTenant(c, existingTenant); err != nil {
		s.logger.WithError(err).Error("Failed to save tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update tenant"})
		return
	}

	c.JSON(http.StatusOK, existingTenant)
}

func (s *AdminServer) deleteTenant(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	tenant, err := s.getTenant(c, tenantID)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant"})
		return
	}

	// Delete tenant key
	tenantKey := fmt.Sprintf("tenant:%s", tenantID)
	if err := s.cache.Del(c, tenantKey); err != nil {
		s.logger.WithError(err).Error("Failed to delete tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete tenant"})
		return
	}

	// Delete subdomain mapping
	subdomainKey := fmt.Sprintf("subdomain:%s", tenant.Subdomain)
	_ = s.cache.Del(c, subdomainKey)

	// Delete associated rules
	rulesKey := fmt.Sprintf("rules:%s", tenantID)
	_ = s.cache.Del(c, rulesKey)

	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted successfully"})
}

// Helper methods
func (s *AdminServer) saveTenant(c *gin.Context, tenant *types.Tenant) error {
	key := fmt.Sprintf("tenant:%s", tenant.ID)
	tenantJSON, err := json.Marshal(tenant)
	if err != nil {
		return err
	}

	return s.cache.Set(c, key, string(tenantJSON), 0)
}

// API Key Management
func (s *AdminServer) createAPIKey(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	// Verify tenant exists
	existingTenant, err := s.getTenant(c, tenantID)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Verify tenant is active
	if existingTenant.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tenant is not active"})
		return
	}

	var req types.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := types.APIKey{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Key:       utils.GenerateApiKey(),
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		ExpiresAt: req.ExpiresAt,
		Status:    "active",
	}

	// Store API key
	key := fmt.Sprintf("apikey:%s:%s", tenantID, apiKey.ID)
	apiKeyJSON, err := json.Marshal(apiKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	if err := s.cache.Set(c, key, string(apiKeyJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to store API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Add to tenant's API keys set
	setKey := fmt.Sprintf("tenant:%s:apikeys", tenantID)
	if err := s.cache.SAdd(c, setKey, apiKey.ID); err != nil {
		s.logger.WithError(err).Error("Failed to add API key to tenant's set")
		// Try to rollback
		s.cache.Del(c, key)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	c.JSON(http.StatusCreated, apiKey)
}

func (s *AdminServer) listAPIKeys(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	// Verify tenant exists
	if _, err := s.getTenant(c, tenantID); err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	// Get API key IDs from set
	setKey := fmt.Sprintf("tenant:%s:apikeys", tenantID)
	keyIDs, err := s.cache.SMembers(c, setKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get API key IDs")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	var apiKeys []types.APIKey
	for _, keyID := range keyIDs {
		key := fmt.Sprintf("apikey:%s:%s", tenantID, keyID)
		apiKeyJSON, err := s.cache.Get(c, key)
		if err != nil {
			continue
		}

		var apiKey types.APIKey
		if err := json.Unmarshal([]byte(apiKeyJSON), &apiKey); err != nil {
			continue
		}

		// Don't expose the actual key
		apiKey.Key = ""
		apiKeys = append(apiKeys, apiKey)
	}

	c.JSON(http.StatusOK, gin.H{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}

func (s *AdminServer) getAPIKeyHandler(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	keyID := c.Param("key_id")

	key := fmt.Sprintf("apikey:%s:%s", tenantID, keyID)
	apiKeyJSON, err := s.cache.Get(c, key)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API key"})
		return
	}

	var apiKey types.APIKey
	if err := json.Unmarshal([]byte(apiKeyJSON), &apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get API key"})
		return
	}

	// Don't expose the actual key
	apiKey.Key = ""
	c.JSON(http.StatusOK, apiKey)
}

func (s *AdminServer) revokeAPIKey(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	keyID := c.Param("key_id")

	key := fmt.Sprintf("apikey:%s:%s", tenantID, keyID)
	apiKeyJSON, err := s.cache.Get(c, key)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	var apiKey types.APIKey
	if err := json.Unmarshal([]byte(apiKeyJSON), &apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	apiKey.Status = "revoked"
	apiKey.Key = "" // Clear the key

	// Save updated API key
	updatedJSON, err := json.Marshal(apiKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	if err := s.cache.Set(c, key, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}

// Forwarding Rule Management
func (s *AdminServer) createForwardingRule(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	// Verify tenant exists and is active
	tenant, err := s.getTenant(c, tenantID)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusNotFound, gin.H{"error": "Tenant not found"})
			return
		}
		s.logger.WithError(err).Error("Failed to get tenant")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	if tenant.Status != "active" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Tenant is not active"})
		return
	}

	var req types.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate plugins against tenant's enabled plugins
	for _, plugin := range req.PluginChain {
		if !isPluginEnabled(plugin.Name, tenant.EnabledPlugins) {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Plugin '%s' is not enabled for this tenant", plugin.Name),
			})
			return
		}
	}

	// Add required plugins if not present
	finalPluginChain := s.mergeRequiredPlugins(tenant.RequiredPlugins, req.PluginChain)

	rule := types.ForwardingRule{
		ID:            uuid.New().String(),
		TenantID:      tenantID,
		Path:          req.Path,
		Target:        req.Target,
		Methods:       req.Methods,
		Headers:       req.Headers,
		StripPath:     req.StripPath != nil && *req.StripPath,
		PreserveHost:  req.PreserveHost != nil && *req.PreserveHost,
		RetryAttempts: defaultIfNil(req.RetryAttempts, 0),
		PluginChain:   finalPluginChain,
		Active:        true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Store rule
	if err := s.saveForwardingRule(c, &rule); err != nil {
		s.logger.WithError(err).Error("Failed to save rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

func (s *AdminServer) listForwardingRules(c *gin.Context) {
	tenantID := c.Param("tenant_id")

	// Get rules from cache
	rules, err := s.getForwardingRules(c, tenantID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

func (s *AdminServer) updateForwardingRule(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	ruleID := c.Param("rule_id")

	// Get existing rule
	rules, err := s.getForwardingRules(c, tenantID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	var rule *types.ForwardingRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}

	if rule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	var req types.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields if provided
	if req.Path != "" {
		rule.Path = req.Path
	}
	if req.Target != "" {
		rule.Target = req.Target
	}
	if len(req.Methods) > 0 {
		rule.Methods = req.Methods
	}
	if req.Headers != nil {
		rule.Headers = req.Headers
	}
	if req.StripPath != nil {
		rule.StripPath = *req.StripPath
	}
	if req.PreserveHost != nil {
		rule.PreserveHost = *req.PreserveHost
	}
	if req.RetryAttempts != nil {
		rule.RetryAttempts = *req.RetryAttempts
	}
	if req.Active != nil {
		rule.Active = *req.Active
	}
	if len(req.PluginChain) > 0 {
		rule.PluginChain = req.PluginChain
	}

	rule.UpdatedAt = time.Now()

	// Save updated rules
	if err := s.saveForwardingRules(c, tenantID, rules); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	c.JSON(http.StatusOK, rule)
}

func (s *AdminServer) deleteForwardingRule(c *gin.Context) {
	tenantID := c.Param("tenant_id")
	ruleID := c.Param("rule_id")

	// Get existing rules
	rules, err := s.getForwardingRules(c, tenantID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// Find and remove the rule
	var newRules []types.ForwardingRule
	found := false
	for _, rule := range rules {
		if rule.ID != ruleID {
			newRules = append(newRules, rule)
		} else {
			found = true
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	if err := s.saveForwardingRules(c, tenantID, newRules); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// Helper functions
func (s *AdminServer) getForwardingRules(c *gin.Context, tenantID string) ([]types.ForwardingRule, error) {
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := s.cache.Get(c, key)
	if err != nil {
		if err.Error() == "redis: nil" {
			return []types.ForwardingRule{}, nil
		}
		return nil, err
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, err
	}

	return rules, nil
}

func (s *AdminServer) saveForwardingRules(c *gin.Context, tenantID string, rules []types.ForwardingRule) error {
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	return s.cache.Set(c, key, string(rulesJSON), 0)
}

func (s *AdminServer) saveForwardingRule(c *gin.Context, rule *types.ForwardingRule) error {
	rules, err := s.getForwardingRules(c, rule.TenantID)
	if err != nil {
		return err
	}

	rules = append(rules, *rule)
	return s.saveForwardingRules(c, rule.TenantID, rules)
}

func isPluginEnabled(pluginName string, enabledPlugins []string) bool {
	for _, enabled := range enabledPlugins {
		if enabled == pluginName {
			return true
		}
	}
	return false
}

func (s *AdminServer) mergeRequiredPlugins(required map[string]types.PluginConfig, requested []types.PluginConfig) []types.PluginConfig {
	result := make([]types.PluginConfig, 0)

	// Add required plugins first
	for _, plugin := range required {
		result = append(result, plugin)
	}

	// Add requested plugins if they're not already required
	for _, plugin := range requested {
		if _, isRequired := required[plugin.Name]; !isRequired {
			result = append(result, plugin)
		}
	}

	return result
}

func defaultIfNil[T any](ptr *T, defaultValue T) T {
	if ptr == nil {
		return defaultValue
	}
	return *ptr
}
