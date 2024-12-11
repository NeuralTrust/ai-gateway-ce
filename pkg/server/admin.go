package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/internal/cache"
	"ai-gateway-ce/internal/database"
	"ai-gateway-ce/internal/models"
	"ai-gateway-ce/internal/types"
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

func convertHeadersToSlice(headers map[string]string) []string {
	var result []string
	for k, v := range headers {
		result = append(result, fmt.Sprintf("%s:%s", k, v))
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
			gateways.POST("", s.createGateway)
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
func (s *AdminServer) createGateway(c *gin.Context) {
	var req types.CreateGatewayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate subdomain format
	if err := validate.Var(req.Subdomain, "subdomain"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid subdomain format"})
		return
	}

	// Check if subdomain is available
	available, err := s.repo.IsSubdomainAvailable(req.Subdomain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to check subdomain availability")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	if !available {
		c.JSON(http.StatusConflict, gin.H{"error": "Subdomain already taken"})
		return
	}

	// Convert types.Gateway to database.Gateway
	dbGateway := &models.Gateway{
		ID:             uuid.New().String(),
		Name:           req.Name,
		Subdomain:      req.Subdomain,
		Status:         "active",
		Tier:           req.Tier,
		EnabledPlugins: req.EnabledPlugins,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.repo.CreateGateway(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to create gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gateway"})
		return
	}

	// Store gateway in cache
	gatewayKey := fmt.Sprintf("gateway:%s", dbGateway.ID)
	gatewayJSON, err := json.Marshal(dbGateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal gateway")
		// Continue anyway as gateway is in DB
	} else {
		if err := s.cache.Set(c, gatewayKey, string(gatewayJSON), 0); err != nil {
			s.logger.WithError(err).Error("Failed to cache gateway")
			// Continue anyway as gateway is in DB
		}
	}

	// Store subdomain mapping
	subdomainKey := fmt.Sprintf("subdomain:%s", dbGateway.Subdomain)
	if err := s.cache.Set(c, subdomainKey, dbGateway.ID, 0); err != nil {
		s.logger.WithError(err).Error("Failed to cache subdomain mapping")
		// Don't return error here, as gateway is already created
		// Just log the error and continue
	}

	// Initialize empty rules in cache
	rulesKey := fmt.Sprintf("rules:%s", dbGateway.ID)
	if err := s.cache.Set(c, rulesKey, "[]", 0); err != nil {
		s.logger.WithError(err).Error("Failed to initialize rules cache")
		// Don't return error here, as gateway is already created
		// Just log the error and continue
	}

	// Convert back to API type
	apiGateway, err := s.convertDBGatewayToAPI(dbGateway)
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

	// Don't expose API key
	gateway.ApiKey = ""
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

func (s *AdminServer) cacheGateway(c *gin.Context, gateway *types.Gateway) error {
	key := fmt.Sprintf("gateway:%s", gateway.ID)
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return err
	}

	return s.cache.Set(c, key, string(gatewayJSON), 0)
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
		existingPlugins := make(map[string]interface{})
		if dbGateway.RequiredPlugins != nil {
			existingPlugins = dbGateway.RequiredPlugins
		}

		// Merge with new plugins
		for k, v := range req.RequiredPlugins {
			existingPlugins[k] = v
		}

		dbGateway.RequiredPlugins = models.JSONMap(existingPlugins)
	}

	dbGateway.UpdatedAt = time.Now()

	if err := s.repo.UpdateGateway(c, dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update gateway"})
		return
	}

	requiredPlugins, err := dbGateway.RequiredPlugins.ToPluginConfigMap()
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert required plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
		return
	}

	response := types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		ApiKey:          dbGateway.ApiKey,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		EnabledPlugins:  []string(dbGateway.EnabledPlugins),
		RequiredPlugins: requiredPlugins,
	}

	if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

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

// Helper methods
func (s *AdminServer) saveGateway(c *gin.Context, gateway *types.Gateway) error {
	key := fmt.Sprintf("gateway:%s", gateway.ID)
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return err
	}

	return s.cache.Set(c, key, string(gatewayJSON), 0)
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

func (s *AdminServer) revokeAPIKey(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	keyID := c.Param("key_id")

	// Delete from database
	if err := s.repo.DeleteAPIKey(c, keyID, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to revoke API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key"})
		return
	}

	// Delete from cache
	key := fmt.Sprintf("apikey:%s:%s", gatewayID, keyID)
	if err := s.cache.Delete(c, key); err != nil {
		s.logger.WithError(err).Error("Failed to remove API key from cache")
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked successfully"})
}

// Forwarding Rule Management
func (s *AdminServer) createForwardingRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
		"method":     c.Request.Method,
		"path":       c.Request.URL.Path,
	}).Info("Creating forwarding rule")

	// Verify gateway exists and is active
	dbGateway, err := s.repo.GetGateway(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Gateway not found: %v", err)})
		return
	}

	if dbGateway.Status != "active" {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
			"status":     dbGateway.Status,
		}).Error("Gateway is not active")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Gateway is not active"})
		return
	}

	// Verify API key matches gateway
	apiKey := c.GetHeader("Authorization")
	if !strings.HasPrefix(apiKey, "Bearer ") {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
		}).Error("Missing or invalid Authorization header")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
		return
	}
	apiKey = strings.TrimPrefix(apiKey, "Bearer ")

	if apiKey != dbGateway.ApiKey {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": gatewayID,
		}).Error("Invalid API key")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		return
	}

	var req types.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"request": req,
	}).Info("Received rule creation request")

	// Convert methods to string array
	var methods []string
	if len(req.Methods) > 0 {
		methods = req.Methods
	} else {
		methods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	}

	// Convert plugin chain to JSON array
	pluginChainJSON, err := json.Marshal(req.PluginChain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal plugin chain")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	var dbPluginChain database.JSONArray
	if err := dbPluginChain.Scan(pluginChainJSON); err != nil {
		s.logger.WithError(err).Error("Failed to scan plugin chain")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	rule := &models.ForwardingRule{
		ID:            uuid.New().String(),
		GatewayID:     gatewayID,
		Path:          req.Path,
		Target:        req.Target,
		Methods:       pq.StringArray(methods),
		Headers:       pq.StringArray(convertMapToHeaders(req.Headers)),
		StripPath:     req.StripPath != nil && *req.StripPath,
		PreserveHost:  req.PreserveHost != nil && *req.PreserveHost,
		RetryAttempts: defaultIfNil(req.RetryAttempts, 0),
		PluginChain:   models.JSONMap{},
		Active:        true,
		Public:        false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	s.logger.WithFields(logrus.Fields{
		"rule": rule,
	}).Info("Created rule object")

	// Store in database
	if err := s.repo.CreateRule(c, rule); err != nil {
		s.logger.WithError(err).Error("Failed to create rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	s.logger.Info("Successfully stored rule in database")

	// Update rules cache
	if err := s.updateRulesCache(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to update rules cache")
	}

	s.logger.Info("Successfully updated rules cache")

	// Convert plugin chain back to array for response
	var pluginChain []types.PluginConfig
	if err := json.Unmarshal(pluginChainJSON, &pluginChain); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal plugin chain for response")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	response := s.getRuleResponse(rule)
	c.JSON(http.StatusCreated, response)
}

func (s *AdminServer) listForwardingRules(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Get rules from database
	dbRules, err := s.repo.ListRules(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
	}

	// Convert to API response type
	var rules []types.ForwardingRule
	for _, dbRule := range dbRules {
		rules = append(rules, s.getRuleResponse(&dbRule))
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

func (s *AdminServer) updateForwardingRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	// Get existing rule
	dbRule, err := s.repo.GetRule(c, ruleID, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rule")
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
		dbRule.Path = req.Path
	}
	if req.Target != "" {
		dbRule.Target = req.Target
	}
	if len(req.Methods) > 0 {
		dbRule.Methods = pq.StringArray(req.Methods)
	}
	if req.Headers != nil {
		dbRule.Headers = pq.StringArray(convertMapToHeaders(req.Headers))
	}
	if req.StripPath != nil {
		dbRule.StripPath = *req.StripPath
	}
	if req.PreserveHost != nil {
		dbRule.PreserveHost = *req.PreserveHost
	}
	if req.RetryAttempts != nil {
		dbRule.RetryAttempts = *req.RetryAttempts
	}
	if req.Active != nil {
		dbRule.Active = *req.Active
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
		dbRule.PluginChain = models.JSONMap(jsonMap)
	}

	dbRule.UpdatedAt = time.Now()

	// Save updated rule
	if err := s.repo.UpdateRule(c, dbRule); err != nil {
		s.logger.WithError(err).Error("Failed to update rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// Update rules cache
	if err := s.updateRulesCache(c.Request.Context(), gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to update rules cache")
	}

	// Convert response
	response := s.getRuleResponse(dbRule)
	c.JSON(http.StatusOK, response)
}

func (s *AdminServer) deleteForwardingRule(c *gin.Context) {
	gatewayID := c.Param("gateway_id")
	ruleID := c.Param("rule_id")

	// Delete from database
	if err := s.repo.DeleteRule(c, ruleID, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to delete rule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// Update rules cache
	s.updateRulesCache(c, gatewayID)

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}

// Helper functions
func (s *AdminServer) getForwardingRules(c *gin.Context, gatewayID string) ([]types.ForwardingRule, error) {
	key := fmt.Sprintf("rules:%s", gatewayID)
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

func (s *AdminServer) saveForwardingRules(c *gin.Context, gatewayID string, rules []types.ForwardingRule) error {
	key := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	return s.cache.Set(c, key, string(rulesJSON), 0)
}

func (s *AdminServer) saveForwardingRule(c *gin.Context, rule *types.ForwardingRule) error {
	rules, err := s.getForwardingRules(c, rule.GatewayID)
	if err != nil {
		return err
	}

	rules = append(rules, *rule)
	return s.saveForwardingRules(c, rule.GatewayID, rules)
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

func (s *AdminServer) getGatewayByID(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	dbGateway, err := s.repo.GetGateway(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	requiredPlugins, err := dbGateway.RequiredPlugins.ToPluginConfigMap()
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert required plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
		return
	}

	gateway := types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		ApiKey:          dbGateway.ApiKey,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		EnabledPlugins:  []string(dbGateway.EnabledPlugins),
		RequiredPlugins: requiredPlugins,
	}

	c.JSON(http.StatusOK, gateway)
}

func (s *AdminServer) getGatewayBySubdomain(c *gin.Context) {
	subdomain := c.Param("subdomain")

	dbGateway, err := s.repo.GetGatewayBySubdomain(c, subdomain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	gateway, err := s.convertDBGatewayToAPI(dbGateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
		return
	}

	if err := s.updateGatewayCache(c.Request.Context(), dbGateway); err != nil {
		s.logger.WithError(err).Error("Failed to update gateway cache")
	}

	c.JSON(http.StatusOK, gateway)
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
	// Add validation for gateway ID
	if err := validateGatewayID(dbGateway.ID); err != nil {
		return nil, fmt.Errorf("invalid gateway data: %w", err)
	}

	// Initialize RequiredPlugins if it's nil or invalid
	if !dbGateway.RequiredPlugins.IsValid() {
		s.logger.WithFields(logrus.Fields{
			"gateway_id": dbGateway.ID,
			"plugins":    dbGateway.RequiredPlugins.String(),
		}).Warn("Invalid or empty RequiredPlugins, resetting to empty object")

		// Create empty plugins map and marshal to JSON
		dbGateway.RequiredPlugins = models.EmptyJSONMap()
	}

	requiredPlugins, err := dbGateway.RequiredPlugins.ToPluginConfigMap()
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"gateway_id": dbGateway.ID,
			"plugins":    dbGateway.RequiredPlugins.String(),
		}).Error("Failed to convert required plugins")
		// Reset to empty object on error
		dbGateway.RequiredPlugins = models.EmptyJSONMap()
		requiredPlugins = map[string]types.PluginConfig{}
	}

	return &types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		ApiKey:          dbGateway.ApiKey,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		EnabledPlugins:  []string(dbGateway.EnabledPlugins),
		RequiredPlugins: requiredPlugins,
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
			dbGateway.RequiredPlugins = models.EmptyJSONMap()
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

// validateSubdomain checks if a subdomain string meets the required format
func validateSubdomain(subdomain string) bool {
	// Only allow lowercase letters, numbers, and hyphens
	// Must start and end with alphanumeric character
	// Length between 3-63 characters
	matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`, subdomain)
	return matched
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

func convertDBJSONMapToMap(headers database.JSONMap) map[string]string {
	result := make(map[string]string)
	var rawMap map[string]interface{}
	if err := json.Unmarshal([]byte(headers), &rawMap); err != nil {
		return result
	}
	for k, v := range rawMap {
		if strVal, ok := v.(string); ok {
			result[k] = strVal
		}
	}
	return result
}

func convertMapToDBJSONMap(headers map[string]string) database.JSONMap {
	data, err := json.Marshal(headers)
	if err != nil {
		return database.JSONMap("{}")
	}
	return database.JSONMap(data)
}

func dbToGateway(dbGateway *database.Gateway) types.Gateway {
	var requiredPlugins map[string]types.PluginConfig
	if err := json.Unmarshal([]byte(dbGateway.RequiredPlugins), &requiredPlugins); err != nil {
		requiredPlugins = make(map[string]types.PluginConfig)
	}

	return types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		ApiKey:          dbGateway.ApiKey,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt.Format(time.RFC3339),
		UpdatedAt:       dbGateway.UpdatedAt.Format(time.RFC3339),
		EnabledPlugins:  []string(dbGateway.EnabledPlugins),
		RequiredPlugins: requiredPlugins,
	}
}

func dbToRule(dbRule *database.ForwardingRule) types.ForwardingRule {
	var pluginChain []types.PluginConfig
	if err := json.Unmarshal([]byte(dbRule.PluginChain), &pluginChain); err != nil {
		pluginChain = make([]types.PluginConfig, 0)
	}

	return types.ForwardingRule{
		ID:            dbRule.ID,
		GatewayID:     dbRule.GatewayID,
		Path:          dbRule.Path,
		Target:        dbRule.Target,
		Methods:       []string(dbRule.Methods),
		Headers:       convertDBJSONMapToMap(dbRule.Headers),
		StripPath:     dbRule.StripPath,
		PreserveHost:  dbRule.PreserveHost,
		RetryAttempts: dbRule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        dbRule.Active,
		Public:        dbRule.Public,
		CreatedAt:     dbRule.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     dbRule.UpdatedAt.Format(time.RFC3339),
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
