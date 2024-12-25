package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	"ai-gateway-ce/pkg/config"
	"ai-gateway-ce/pkg/database"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/pluginiface"
	"ai-gateway-ce/pkg/plugins"
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

type AdminServer struct {
	*BaseServer
}

func NewAdminServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger, eePlugins ...pluginiface.Plugin) *AdminServer {
	// Initialize plugins
	plugins.InitializePlugins(cache, logger)

	// Register extra plugins
	for _, plugin := range eePlugins {
		plugins.GetManager().RegisterPlugin(plugin)
	}

	return &AdminServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
	}
}

func (s *AdminServer) AddRoutes(router *gin.RouterGroup) {
	// Base routes that are common to both CE and EE editions
	s.addBaseRoutes(router)

	// Note: EE version can call this method and then add its own additional routes
}

// addBaseRoutes adds the core/common routes used in both CE and EE editions
func (s *AdminServer) addBaseRoutes(router *gin.RouterGroup) {
	v1 := router.Group("/api/v1")
	{
		gateways := v1.Group("/gateways")
		{
			gateways.POST("", s.CreateGateway)
			gateways.GET("", s.listGateways)
			gateways.GET("/:gateway_id", s.getGatewayHandler)
			gateways.PUT("/:gateway_id", s.updateGateway)
			gateways.DELETE("/:gateway_id", s.handleDeleteGateway)

			// Rules management
			rules := gateways.Group("/:gateway_id/rules")
			{
				rules.GET("", s.listRules)
				rules.POST("", s.createRule)
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

func (s *AdminServer) setupRoutes() {
	// Create the base router group and add routes to it
	baseRouter := s.router.Group("")
	s.AddRoutes(baseRouter)
}

func (s *AdminServer) Run() error {
	// Set up routes
	s.setupRoutes()

	// Start the server
	addr := fmt.Sprintf(":%d", s.config.Server.AdminPort)
	defer s.logger.WithField("addr", addr).Info("Starting admin server")
	return s.runServer(addr)
}

// Gateway Management
func (s *AdminServer) CreateGateway(c *gin.Context) {
	var gateway models.Gateway
	if err := c.ShouldBindJSON(&gateway); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set timestamps
	now := time.Now()
	gateway.CreatedAt = now
	gateway.UpdatedAt = now

	// Create gateway
	if err := s.repo.CreateGateway(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to create gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := s.updateGatewayCache(c.Request.Context(), &gateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	c.JSON(http.StatusCreated, gateway)
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

	if req.RequiredPlugins != nil {
		// Initialize plugins map
		if dbGateway.RequiredPlugins == nil {
			dbGateway.RequiredPlugins = []types.PluginConfig{}
		}

		// Convert and validate plugins
		manager := plugins.GetManager()
		for _, config := range req.RequiredPlugins {
			if err := manager.ValidatePlugin(config.Name, config); err != nil {
				s.logger.WithError(err).WithField("plugin", config.Name).Error("Invalid plugin configuration")
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid plugin configuration: %v", err)})
				return
			}
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
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		RequiredPlugins: apiGateway.RequiredPlugins,
	}

	if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	// Invalidate caches
	s.invalidateCaches(dbGateway.ID)

	c.JSON(http.StatusOK, response)
}

func (s *AdminServer) handleDeleteGateway(c *gin.Context) {
	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id is required"})
		return
	}

	if err := s.repo.DeleteGateway(id); err != nil {
		s.logger.WithError(err).Error("Failed to delete gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
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

	// Generate new API key
	apiKey := &models.APIKey{
		ID:        uuid.NewString(),
		Name:      req.Name,
		GatewayID: gatewayID,
		Key:       generateAPIKey(),
	}

	// Set expiration only if provided
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = *req.ExpiresAt
	}

	// Store in database
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

	var apiKey models.APIKey
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
			"targets": rule.Targets,
			"methods": rule.Methods,
		}).Debug("Converting rule")

		var pluginChain []types.PluginConfig
		if rule.PluginChain != nil {
			chainJSON, _ := json.Marshal(rule.PluginChain)
			if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
				s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
				continue
			}
		}

		// Convert headers from []string to map[string]string
		headers := make(map[string]string)
		for _, h := range rule.Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		apiRules[i] = types.ForwardingRule{
			ID:            rule.ID,
			GatewayID:     rule.GatewayID,
			Path:          rule.Path,
			Targets:       rule.Targets,
			Methods:       []string(rule.Methods),
			Headers:       headers,
			StripPath:     rule.StripPath,
			PreserveHost:  rule.PreserveHost,
			RetryAttempts: rule.RetryAttempts,

			PluginChain: pluginChain,
			Active:      rule.Active,
			Public:      rule.Public,
			CreatedAt:   rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:   rule.UpdatedAt.Format(time.RFC3339),
		}

		s.logger.WithFields(logrus.Fields{
			"rule_id":      apiRules[i].ID,
			"path":         apiRules[i].Path,
			"targets":      apiRules[i].Targets,
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
	if rule.PluginChain != nil {
		// Convert JSONMap directly to []PluginConfig
		chainJSON, _ := json.Marshal(rule.PluginChain)
		if err := json.Unmarshal(chainJSON, &pluginChain); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
			pluginChain = make([]types.PluginConfig, 0)
		}
	}

	// Convert headers from pq.StringArray to map[string]string
	headers := make(map[string]string)
	for _, h := range rule.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return types.ForwardingRule{
		ID:              rule.ID,
		GatewayID:       rule.GatewayID,
		Path:            rule.Path,
		Targets:         []types.ForwardingTarget(rule.Targets),
		FallbackTargets: []types.ForwardingTarget(rule.FallbackTargets),
		Methods:         []string(rule.Methods),
		Headers:         headers,
		StripPath:       rule.StripPath,
		PreserveHost:    rule.PreserveHost,
		RetryAttempts:   rule.RetryAttempts,
		PluginChain:     pluginChain,
		Active:          rule.Active,
		Public:          rule.Public,
		CreatedAt:       rule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       rule.UpdatedAt.Format(time.RFC3339),
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

	// Validate the rule request
	if err := s.validateRule(&req); err != nil {
		s.logger.WithError(err).Error("Rule validation failed")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Convert headers to map[string]string format
	headers := make(map[string]string)
	for k, v := range req.Headers {
		headers[k] = v
	}

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

	// Create the database model
	dbRule := &models.ForwardingRule{
		ID:                  uuid.NewString(),
		GatewayID:           gatewayID,
		Path:                req.Path,
		Targets:             models.TargetsJSON(req.Targets),
		FallbackTargets:     models.TargetsJSON(req.FallbackTargets),
		Methods:             models.MethodsJSON(req.Methods),
		Headers:             models.HeadersJSON(req.Headers),
		StripPath:           stripPath,
		PreserveHost:        preserveHost,
		RetryAttempts:       retryAttempts,
		PluginChain:         req.PluginChain,
		Active:              true,
		Public:              false,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		Credentials:         models.FromCredentials(req.Credentials),
		FallbackCredentials: models.FromCredentials(req.FallbackCredentials),
	}

	// Store in database
	if err := s.repo.CreateRule(c, dbRule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	// Update rules cache
	if err := s.updateRulesCache(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to update rules cache")
		// Continue anyway as rule is in DB
	}

	// Convert database model to API response type
	response := s.getRuleResponse(dbRule)

	// After successfully creating the rule
	if err := s.publishCacheInvalidation(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to publish cache invalidation")
		// Don't return error to client since rule was created successfully
	}

	c.JSON(http.StatusCreated, response)
}

func (s *AdminServer) listRules(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Get rules from database
	dbRules, err := s.repo.ListRules(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules from database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	// Convert to API response format
	rules := make([]types.ForwardingRule, len(dbRules))
	for i, rule := range dbRules {
		rules[i] = types.ForwardingRule{
			ID:            rule.ID,
			GatewayID:     rule.GatewayID,
			Path:          rule.Path,
			Targets:       rule.Targets,
			Methods:       rule.Methods,
			Headers:       rule.Headers,
			StripPath:     rule.StripPath,
			PreserveHost:  rule.PreserveHost,
			RetryAttempts: rule.RetryAttempts,
			PluginChain:   rule.PluginChain,
			Active:        rule.Active,
			Public:        rule.Public,
			CreatedAt:     rule.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     rule.UpdatedAt.Format(time.RFC3339),
		}
	}

	// Cache the rules for future requests
	rulesJSON, err := json.Marshal(rules)
	if err == nil {
		rulesKey := fmt.Sprintf("rules:%s", gatewayID)
		if err := s.cache.Set(c, rulesKey, string(rulesJSON), 0); err != nil {
			s.logger.WithError(err).Warn("Failed to cache rules")
		}
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

	// Convert UpdateRuleRequest to CreateRuleRequest for validation
	validateReq := types.CreateRuleRequest{
		Path:          req.Path,
		Targets:       req.Targets,
		Methods:       req.Methods,
		Headers:       req.Headers,
		StripPath:     req.StripPath,
		PreserveHost:  req.PreserveHost,
		RetryAttempts: req.RetryAttempts,
		PluginChain:   req.PluginChain,
	}

	// Validate the rule request
	if err := s.validateRule(&validateReq); err != nil {
		s.logger.WithError(err).Error("Rule validation failed")
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
			if req.Targets != nil {
				rules[i].Targets = req.Targets
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

func (s *AdminServer) validateRule(rule *types.CreateRuleRequest) error {
	// Validate required fields
	if rule.Path == "" {
		return fmt.Errorf("path is required")
	}

	if len(rule.Methods) == 0 {
		return fmt.Errorf("at least one method is required")
	}

	if len(rule.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}

	// Validate targets
	totalWeight := 0
	hasWeights := false
	for i, target := range rule.Targets {
		if target.URL == "" {
			return fmt.Errorf("target %d: URL is required", i)
		}

		// Validate URL format
		if _, err := url.Parse(target.URL); err != nil {
			return fmt.Errorf("target %d: invalid URL format: %v", i, err)
		}

		if target.Weight > 0 {
			hasWeights = true
			totalWeight += target.Weight
		}
	}

	// If any target has weight, all must have weights summing to 100
	if hasWeights && totalWeight != 100 {
		return fmt.Errorf("when using weighted distribution, weights must sum to 100 (got %d)", totalWeight)
	}

	// Validate methods
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	for _, method := range rule.Methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	// Validate plugin chain if present
	if len(rule.PluginChain) > 0 {
		for i, plugin := range rule.PluginChain {
			if err := s.validatePlugin(plugin); err != nil {
				return fmt.Errorf("plugin %d: %v", i, err)
			}
		}
	}

	return nil
}

func (s *AdminServer) validatePlugin(plugin types.PluginConfig) error {
	// Validate required fields
	if plugin.Name == "" {
		return fmt.Errorf("plugin name is required")
	}

	if plugin.Stage == "" {
		return fmt.Errorf("plugin stage is required")
	}

	// Validate settings
	if plugin.Settings == nil {
		return fmt.Errorf("plugin settings are required")
	}

	// Validate stage
	validStages := map[types.Stage]bool{
		types.PreRequest:   true,
		types.PostRequest:  true,
		types.PreResponse:  true,
		types.PostResponse: true,
	}
	if !validStages[plugin.Stage] {
		return fmt.Errorf("invalid plugin stage: %s", plugin.Stage)
	}

	// Validate priority (0-999)
	if plugin.Priority < 0 || plugin.Priority > 999 {
		return fmt.Errorf("plugin priority must be between 0 and 999")
	}

	// Get plugin validator
	manager := plugins.GetManager()
	if err := manager.ValidatePlugin(plugin.Name, plugin); err != nil {
		return fmt.Errorf("unknown plugin: %s", plugin.Name)
	}
	return nil
}
