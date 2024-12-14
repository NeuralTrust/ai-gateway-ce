package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/common"
	"ai-gateway-ce/pkg/database"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/types"
)

var validate = validator.New()

func init() {
	validate.RegisterValidation("subdomain", validateSubdomainField)
}

func validateSubdomainField(fl validator.FieldLevel) bool {
	subdomain := fl.Field().String()

	if len(subdomain) < 3 || len(subdomain) > 63 {
		return false
	}

	if !isAlphanumeric(subdomain[0]) || !isAlphanumeric(subdomain[len(subdomain)-1]) {
		return false
	}

	for _, c := range subdomain {
		if !isAlphanumeric(byte(c)) && c != '-' {
			return false
		}
	}

	return true
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// Helper functions for header conversion
func convertHeadersToMap(headers []string) map[string]string {
	result := make(map[string]string)
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

type AdminServer struct {
	*BaseServer
}

func NewAdminServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *AdminServer {
	return &AdminServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
	}
}

func (s *AdminServer) setupRoutes() {
	// API v1 group
	v1 := s.router.Group("/api/v1")
	{
		// Gateway routes
		gateways := v1.Group("/gateways")
		{
			gateways.POST("", s.CreateGateway)
			gateways.GET("", s.listGateways)
			gateways.GET("/:gateway_id", s.getGatewayHandler)
			gateways.PUT("/:gateway_id", s.updateGateway)
			gateways.DELETE("/:gateway_id", s.deleteGateway)

			// Rules management
			rules := gateways.Group("/:gateway_id/rules")
			{
				rules.POST("", s.createRule)
				rules.GET("", s.listRules)
				rules.PUT("/:rule_id", s.updateRule)
				rules.DELETE("/:rule_id", s.deleteRule)
			}

			// API key management
			keys := gateways.Group("/:gateway_id/keys")
			{
				keys.POST("", s.createAPIKey)
				keys.GET("", s.listAPIKeys)
				keys.GET("/:key_id", s.getAPIKeyHandler)
				keys.DELETE("/:key_id", s.deleteAPIKey)
			}
		}
	}
}

func (s *AdminServer) Run() error {
	// Set up routes
	s.setupRoutes()

	// Start the server
	addr := fmt.Sprintf(":%d", s.config.AdminPort)
	defer s.logger.WithField("addr", addr).Info("Starting admin server")
	return s.runServer(addr)
}

// Gateway Management
func (s *AdminServer) CreateGateway(c *gin.Context) {
	var gateway models.Gateway
	if err := c.ShouldBindJSON(&gateway); err != nil {
		s.logger.WithError(err).Error("Failed to bind JSON")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	exists, err := s.repo.SubdomainExists(c.Request.Context(), gateway.Subdomain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check subdomain availability")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check subdomain availability"})
		return
	}
	if exists {
		s.logger.WithField("subdomain", gateway.Subdomain).Error("Subdomain already exists")
		c.JSON(http.StatusConflict, gin.H{"error": "Subdomain already exists"})
		return
	}

	// Validate required plugins
	for _, plugin := range gateway.RequiredPlugins {
		if err := s.validatePluginConfig(plugin); err != nil {
			s.logger.WithError(err).WithField("plugin", plugin.Name).Error("Invalid plugin configuration")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid plugin configuration: %v", err)})
			return
		}
	}

	s.logger.WithFields(logrus.Fields{
		"gateway":          gateway,
		"enabled_plugins":  gateway.EnabledPlugins,
		"required_plugins": gateway.RequiredPlugins,
	}).Info("Creating gateway - received request")

	// Initialize RequiredPlugins as slice if nil
	if gateway.RequiredPlugins == nil {
		s.logger.Debug("Initializing empty RequiredPlugins slice")
		gateway.RequiredPlugins = make([]types.PluginConfig, 0)
	}

	// Validate that all required plugins are also enabled
	for _, plugin := range gateway.RequiredPlugins {
		found := false
		for _, enabled := range gateway.EnabledPlugins {
			if enabled == plugin.Name {
				found = true
				break
			}
		}
		if !found {
			s.logger.WithFields(logrus.Fields{
				"plugin":          plugin.Name,
				"enabled_plugins": gateway.EnabledPlugins,
			}).Error("Plugin required but not enabled")
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("Plugin %s is required but not enabled. Required plugins must be in the enabled plugins list.", plugin.Name),
			})
			return
		}
	}

	// Set default status if not provided
	if gateway.Status == "" {
		gateway.Status = "active"
	}

	// Create gateway
	if err := s.repo.CreateGateway(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to create gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"gateway_id":       gateway.ID,
		"required_plugins": gateway.RequiredPlugins,
	}).Info("Gateway created successfully")

	// Cache the gateway data
	if err := s.updateGatewayCache(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to cache gateway")
	}

	// Cache the subdomain mapping
	subdomainKey := fmt.Sprintf("subdomain:%s", gateway.Subdomain)
	if err := s.cache.Set(c.Request.Context(), subdomainKey, gateway.ID, 0); err != nil {
		s.logger.WithError(err).Error("Failed to cache subdomain mapping")
	}

	// Convert to API response
	apiGateway, err := s.convertDBGatewayToAPI(&gateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway"})
		return
	}

	c.JSON(http.StatusCreated, apiGateway)
}

func generateAPIKey() string {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return uuid.NewString() // Fallback to UUID if crypto/rand fails
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *AdminServer) listGateways(c *gin.Context) {
	offset := 0
	limit := 10

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if val, err := strconv.Atoi(offsetStr); err == nil {
			offset = val
		}
	}
	if limitStr := c.Query("limit"); limitStr != "" {
		if val, err := strconv.Atoi(limitStr); err == nil && val > 0 && val <= 100 {
			limit = val
		}
	}

	dbGateways, err := s.repo.ListGateways(c, offset, limit)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list gateways")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list gateways"})
		return
	}

	var gateways []types.Gateway
	for _, dbGateway := range dbGateways {
		gateway, err := s.convertDBGatewayToAPI(&dbGateway)
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert gateway")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
			return
		}
		gateways = append(gateways, *gateway)

		// Update cache in background
		go func(g models.Gateway) {
			ctx := context.Background()
			if err := s.updateGatewayCache(ctx, &g); err != nil {
				s.logger.WithError(err).Error("Failed to update gateway cache")
			}
		}(dbGateway)
	}

	c.JSON(http.StatusOK, gin.H{
		"gateways": gateways,
		"count":    len(gateways),
		"offset":   offset,
		"limit":    limit,
	})
}

func (s *AdminServer) getGatewayHandler(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Add request details logging
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
		"user_agent": c.Request.UserAgent(),
		"referer":    c.Request.Referer(),
	}).Info("Gateway retrieval request received")

	// Add validation for gateway ID
	if gatewayID == "" || gatewayID == "null" {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"user_agent": c.Request.UserAgent(),
			"referer":    c.Request.Referer(),
		}).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid gateway ID"})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid UUID format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid gateway ID format"})
		return
	}

	s.logger.WithField("gateway_id", gatewayID).Info("Getting gateway")
	// Try to get from cache first
	gateway, err := s.getGatewayFromCache(c, gatewayID)
	if err != nil {
		// If not in cache, get from database
		dbGateway, err := s.repo.GetGateway(c, gatewayID)
		if err != nil {
			s.logger.WithError(err).Error("Failed to get gateway")
			c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
			return
		}

		// Convert to API type
		gateway, err = s.convertDBGatewayToAPI(dbGateway)
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert gateway")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
			return
		}

		// Store in cache
		if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
			s.logger.WithError(err).Error("Failed to cache gateway")
		}
	}

	c.JSON(http.StatusOK, gateway)
}

func (s *AdminServer) getGatewayFromCache(c *gin.Context, id string) (*types.Gateway, error) {
	if err := validateGatewayID(id); err != nil {
		return nil, err
	}

	key := fmt.Sprintf("gateway:%s", id)
	gatewayJSON, err := s.cache.Get(c, key)
	if err != nil {
		return nil, err
	}

	var gateway types.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, err
	}

	return &gateway, nil
}

func (s *AdminServer) updateGateway(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	if err := validateGatewayID(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dbGateway, err := s.repo.GetGateway(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	var req types.UpdateGatewayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		dbGateway.Name = *req.Name
	}
	if req.Status != nil {
		dbGateway.Status = *req.Status
	}
	if req.Tier != nil {
		dbGateway.Tier = *req.Tier
	}
	if req.EnabledPlugins != nil {
		dbGateway.EnabledPlugins = pq.StringArray(req.EnabledPlugins)
	}
	if req.RequiredPlugins != nil {
		// Initialize plugins map
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		// Convert and validate plugins
		for _, config := range req.RequiredPlugins {
			dbGateway.RequiredPlugins = append(dbGateway.RequiredPlugins, config)
		}
	}

	dbGateway.UpdatedAt = time.Now()

	if err := s.repo.UpdateGateway(c, dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update gateway"})
		return
	}

	// Convert to response type
	apiGateway, err := s.convertDBGatewayToAPI(dbGateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway"})
		return
	}

	response := types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		EnabledPlugins:  dbGateway.EnabledPlugins,
		RequiredPlugins: apiGateway.RequiredPlugins,
	}

	if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	// Invalidate caches
	s.invalidateCaches(dbGateway.ID)

	c.JSON(http.StatusOK, response)
}

func (s *AdminServer) deleteGateway(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	if err := validateGatewayID(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get gateway first to get the subdomain
	gateway, err := s.getGatewayFromCache(c, gatewayID)
	if err != nil {
		dbGateway, err := s.repo.GetGateway(c, gatewayID)
		if err != nil {
			s.logger.WithError(err).Error("Failed to get gateway")
			c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
			return
		}
		gateway = &types.Gateway{
			ID:        dbGateway.ID,
			Subdomain: dbGateway.Subdomain,
		}
	}

	// Delete from database (this will cascade to rules and API keys)
	if err := s.repo.DeleteGateway(c, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to delete gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete gateway"})
		return
	}

	// Delete from cache
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	subdomainKey := fmt.Sprintf("subdomain:%s", gateway.Subdomain)
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)

	_ = s.cache.Delete(c, gatewayKey)
	_ = s.cache.Delete(c, subdomainKey)
	_ = s.cache.Delete(c, rulesKey)

	// Update gateways list in cache
	if err := s.updateGatewaysList(c); err != nil {
		s.logger.WithError(err).Error("Failed to update gateways list")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Gateway deleted successfully"})
}

// API Key Management
func (s *AdminServer) createAPIKey(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	var req types.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := &models.APIKey{
		GatewayID: gatewayID,
		Name:      req.Name,
		Key:       generateAPIKey(),
		Active:    true,
		ExpiresAt: req.ExpiresAt,
	}

	if err := s.repo.CreateAPIKey(c, apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to create API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Save to cache
	if err := s.cache.SaveAPIKey(c, apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to cache API key")
		// Continue anyway as key is in DB
	}

	c.JSON(http.StatusCreated, apiKey)
}

func (s *AdminServer) listAPIKeys(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Verify gateway exists
	if _, err := s.repo.GetGateway(c, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	// Get API keys from database
	apiKeys, err := s.repo.ListAPIKeys(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list API keys")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list API keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_keys": apiKeys,
		"count":    len(apiKeys),
	})
}

func (s *AdminServer) getAPIKeyHandler(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	keyID := c.Param("key_id")

	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
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

func (s *AdminServer) updateRulesCache(ctx context.Context, gatewayID string) error {
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
	}).Info("Updating rules cache")

	// Get rules from database
	rules, err := s.repo.ListRules(ctx, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list rules")
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"rules_count": len(rules),
		"rules":       rules,
	}).Debug("Retrieved rules from database")

	// Convert database rules to API rules
	apiRules := make([]types.ForwardingRule, len(rules))
	for i, rule := range rules {
		s.logger.WithFields(logrus.Fields{
			"rule_id": rule.ID,
			"path":    rule.Path,
			"target":  rule.Target,
			"methods": rule.Methods,
		}).Debug("Converting rule")

		// Convert plugin chain from JSON string to array
		var pluginChain []types.PluginConfig
		if len(rule.PluginChain) > 0 {
			var wrapper struct {
				Plugins []types.PluginConfig `json:"plugins"`
			}
			if err := json.Unmarshal(rule.PluginChain.ToBytes(), &wrapper); err != nil {
				s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
				continue
			}
			pluginChain = wrapper.Plugins
		}

		apiRules[i] = types.ForwardingRule{
			ID:            rule.ID,
			GatewayID:     rule.GatewayID,
			Path:          rule.Path,
			Target:        rule.Target,
			Methods:       []string(rule.Methods),
			Headers:       convertHeadersToMap([]string(rule.Headers)),
			StripPath:     rule.StripPath,
			PreserveHost:  rule.PreserveHost,
			RetryAttempts: rule.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        rule.Active,
			Public:        rule.Public,
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}

		s.logger.WithFields(logrus.Fields{
			"rule_id":      apiRules[i].ID,
			"path":         apiRules[i].Path,
			"target":       apiRules[i].Target,
			"methods":      apiRules[i].Methods,
			"plugin_chain": apiRules[i].PluginChain,
		}).Debug("Converted rule")
	}

	// Marshal rules to JSON
	rulesJSON, err := json.Marshal(apiRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"rules_json": string(rulesJSON),
	}).Debug("Marshaled rules to JSON")

	// Store in cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to store rules in cache")
		return err
	}

	s.logger.Info("Successfully updated rules cache")
	return nil
}

func (s *AdminServer) updateGatewayCache(ctx context.Context, gateway *models.Gateway) error {
	if err := validateGatewayID(gateway.ID); err != nil {
		return fmt.Errorf("invalid gateway ID: %w", err)
	}

	// Convert to API type for caching
	apiGateway, err := s.convertDBGatewayToAPI(gateway)
	if err != nil {
		return fmt.Errorf("failed to convert gateway: %w", err)
	}

	// Cache the gateway
	gatewayJSON, err := json.Marshal(apiGateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}

	key := fmt.Sprintf("gateway:%s", gateway.ID)
	if err := s.cache.Set(ctx, key, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	return nil
}

func (s *AdminServer) convertDBGatewayToAPI(dbGateway *models.Gateway) (*types.Gateway, error) {
	if dbGateway.RequiredPlugins == nil {
		dbGateway.RequiredPlugins = []types.PluginConfig{}
	}

	return &types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		EnabledPlugins:  dbGateway.EnabledPlugins,
		RequiredPlugins: dbGateway.RequiredPlugins,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
	}, nil
}

// updateGatewaysList updates the list of all gateways in Redis
func (s *AdminServer) updateGatewaysList(ctx context.Context) error {
	s.logger.Info("Starting to update gateways list")

	// Get all gateways from database
	gateways, err := s.repo.ListGateways(ctx, 0, 1000)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list gateways from database")
		return fmt.Errorf("failed to list gateways: %w", err)
	}

	s.logger.WithField("count", len(gateways)).Info("Retrieved gateways from database")

	// Convert to API types
	var apiGateways []types.Gateway
	for _, dbGateway := range gateways {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": dbGateway.ID,
			"name":       dbGateway.Name,
			"subdomain":  dbGateway.Subdomain,
		}).Debug("Processing gateway for list")

		// Initialize required plugins if nil
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		apiGateway, err := s.convertDBGatewayToAPI(&dbGateway)
		if err != nil {
			s.logger.WithError(err).WithField("gateway_id", dbGateway.ID).Error("Failed to convert gateway")
			continue
		}
		apiGateways = append(apiGateways, *apiGateway)
	}

	// Store in cache
	gatewaysJSON, err := json.Marshal(apiGateways)
	if err != nil {
		return fmt.Errorf("failed to marshal gateways: %w", err)
	}

	if err := s.cache.Set(ctx, "gateways", string(gatewaysJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateways list: %w", err)
	}

	s.logger.WithField("count", len(apiGateways)).Info("Successfully updated gateways list in cache")
	return nil
}

// Helper function to validate gateway ID format
func validateGatewayID(id string) error {
	if id == "" {
		return fmt.Errorf("gateway ID cannot be empty")
	}

	// Check if it's a valid UUID
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("gateway ID must be a valid UUID: %v", err)
	}

	return nil
}

func (s *AdminServer) getRuleResponse(rule *models.ForwardingRule) types.ForwardingRule {
	var pluginChain []types.PluginConfig
	if len(rule.PluginChain) > 0 {
		// Extract the plugins array from the wrapper
		var wrapper struct {
			Plugins []types.PluginConfig `json:"plugins"`
		}
		if err := json.Unmarshal(rule.PluginChain.ToBytes(), &wrapper); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
			pluginChain = make([]types.PluginConfig, 0)
		} else {
			pluginChain = wrapper.Plugins
		}
	}

	return types.ForwardingRule{
		ID:            rule.ID,
		GatewayID:     rule.GatewayID,
		Path:          rule.Path,
		Target:        rule.Target,
		Methods:       []string(rule.Methods),
		Headers:       convertHeadersToMap([]string(rule.Headers)),
		StripPath:     rule.StripPath,
		PreserveHost:  rule.PreserveHost,
		RetryAttempts: rule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        rule.Active,
		Public:        rule.Public,
		CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
	}
}

// Rule management methods
func (s *AdminServer) createRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	var req types.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate required fields
	if req.Path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}

	// Generate rule ID
	ruleID := uuid.NewString()
	now := time.Now()

	// Set default values for optional fields
	stripPath := false
	if req.StripPath != nil {
		stripPath = *req.StripPath
	}

	preserveHost := false
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}

	retryAttempts := 0
	if req.RetryAttempts != nil {
		retryAttempts = *req.RetryAttempts
	}

	// Convert plugin chain to JSON map
	var pluginChainMap models.JSONMap
	if len(req.PluginChain) > 0 {
		// Create a wrapper map that contains the array
		wrapper := map[string]interface{}{
			"plugins": req.PluginChain,
		}
		pluginChainMap = models.JSONMap(wrapper)
	}

	rule := &models.ForwardingRule{
		ID:            ruleID,
		GatewayID:     gatewayID,
		Path:          req.Path,
		Target:        req.Target,
		Methods:       pq.StringArray(req.Methods),
		Headers:       pq.StringArray(convertMapToHeaders(req.Headers)),
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		PluginChain:   pluginChainMap,
		Active:        true,
		Public:        false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Store in database
	if err := s.repo.CreateRule(c, rule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	// Update rules cache
	if err := s.updateRulesCache(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to update rules cache")
		// Continue anyway as rule is in DB
	}

	// Convert to API response
	response := s.getRuleResponse(rule)

	// After successfully creating the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
		// Don't return error to client since rule was created successfully
	}

	c.JSON(http.StatusCreated, response)
}

func (s *AdminServer) listRules(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Get rules from cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	c.JSON(http.StatusOK, rules)
}

func (s *AdminServer) updateRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	var req types.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing rules
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// Find and update rule
	found := false
	for i, rule := range rules {
		if rule.ID == ruleID {
			if req.Path != "" {
				rules[i].Path = req.Path
			}
			if req.Target != "" {
				rules[i].Target = req.Target
			}
			if len(req.Methods) > 0 {
				rules[i].Methods = pq.StringArray(req.Methods)
			}
			if req.Headers != nil {
				rules[i].Headers = convertMapToDBHeaders(req.Headers)
			}
			if req.StripPath != nil {
				rules[i].StripPath = *req.StripPath
			}
			if req.Active != nil {
				rules[i].Active = *req.Active
			}
			if req.PreserveHost != nil {
				rules[i].PreserveHost = *req.PreserveHost
			}
			if req.RetryAttempts != nil {
				rules[i].RetryAttempts = *req.RetryAttempts
			}
			if req.PluginChain != nil {
				pluginChainBytes, err := json.Marshal(req.PluginChain)
				if err != nil {
					s.logger.WithError(err).Error("Failed to marshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				var pluginChain []types.PluginConfig
				if err := json.Unmarshal(pluginChainBytes, &pluginChain); err != nil {
					s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				pluginChainMap, err := json.Marshal(pluginChain)
				if err != nil {
					s.logger.WithError(err).Error("Failed to marshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				var jsonMap map[string]interface{}
				if err := json.Unmarshal(pluginChainMap, &jsonMap); err != nil {
					s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin chain"})
					return
				}
				rules[i].PluginChain = pluginChain
			}
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(rules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	if err := s.cache.Set(c, rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// After successfully updating the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule updated successfully"})
}

func (s *AdminServer) deleteRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	// Get existing rules
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// Find and remove rule
	found := false
	var updatedRules []types.ForwardingRule
	for _, rule := range rules {
		if rule.ID == ruleID {
			found = true
			continue
		}
		updatedRules = append(updatedRules, rule)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(updatedRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	if err := s.cache.Set(c, rulesKey, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// After successfully deleting the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// API key management methods
func (s *AdminServer) deleteAPIKey(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	keyID := c.Param("key_id")

	// Delete API key from cache
	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	if err := s.cache.Delete(c, key); err != nil {
		s.logger.WithError(err).Error("Failed to delete API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted successfully"})
}

// Add helper function for header conversion
func convertMapToHeaders(headers map[string]string) []string {
	var result []string
	for k, v := range headers {
		result = append(result, fmt.Sprintf("%s: %s", k, v))
	}
	return result
}

func convertMapToDBHeaders(headers map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range headers {
		result[k] = v
	}
	return result
}

func (s *AdminServer) invalidateCaches(gatewayID string) {
	keys := common.GetCacheKeys(gatewayID)

	// Clear Redis caches (affects all replicas)
	s.cache.Delete(context.Background(), keys.Gateway)
	s.cache.Delete(context.Background(), keys.Rules)
	s.cache.Delete(context.Background(), keys.Plugin)

	// Publish cache invalidation event
	s.cache.Client().Publish(context.Background(), "cache:invalidate", gatewayID)
}

func (s *AdminServer) validatePluginConfig(plugin types.PluginConfig) error {
	// Validate required fields
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	// Validate stage
	if plugin.Stage == "" {
		return fmt.Errorf("plugin stage is required")
	}
	validStages := map[types.Stage]bool{
		types.PreRequest:   true,
		types.PostRequest:  true,
		types.PreResponse:  true,
		types.PostResponse: true,
	}
	if !validStages[plugin.Stage] {
		return fmt.Errorf("invalid plugin stage: %s", plugin.Stage)
	}

	// Validate priority (0-999, lower numbers execute first)
	if plugin.Priority < 0 || plugin.Priority > 999 {
		return fmt.Errorf("plugin priority must be between 0 and 999")
	}

	// Validate settings based on plugin type
	switch plugin.Name {
	case "rate_limiter":
		if plugin.Stage != types.PreRequest {
			return fmt.Errorf("rate limiter plugin must be in pre_request stage")
		}
		return validateRateLimiterSettings(plugin.Settings)
	// Add other plugin validations here
	default:
		return fmt.Errorf("unknown plugin: %s", plugin.Name)
	}
}

func validateRateLimiterSettings(settings map[string]interface{}) error {
	// Validate limits
	limits, ok := settings["limits"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("rate limiter requires 'limits' configuration")
	}

	// At least one limit type must be configured
	if len(limits) == 0 {
		return fmt.Errorf("rate limiter requires at least one limit configuration")
	}

	// Validate each limit configuration
	for limitType, config := range limits {
		limitConfig, ok := config.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid limit configuration for %s", limitType)
		}

		// Validate limit value
		limit, ok := limitConfig["limit"].(float64)
		if !ok || limit <= 0 {
			return fmt.Errorf("rate limiter requires positive 'limit' value for %s", limitType)
		}

		// Validate window
		window, ok := limitConfig["window"].(string)
		if !ok || window == "" {
			return fmt.Errorf("rate limiter requires 'window' configuration for %s", limitType)
		}
	}

	// Set default actions if not provided
	if actions, exists := settings["actions"].(map[string]interface{}); !exists || actions == nil {
		settings["actions"] = map[string]interface{}{
			"type":        "reject",
			"retry_after": "60",
		}
	}

	return nil
}

func (s *AdminServer) publishCacheInvalidation(ctx context.Context, gatewayID string) error {
	msg := map[string]string{
		"type":      "cache_invalidation",
		"gatewayID": gatewayID,
	}

	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Get Redis client from cache
	rdb := s.cache.Client()
	return rdb.Publish(ctx, "gateway_events", string(msgJSON)).Err()
}
