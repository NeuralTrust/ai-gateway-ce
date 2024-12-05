package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/database"
	"ai-gateway/internal/types"
	"ai-gateway/internal/utils"
	"crypto/rand"
	"encoding/base64"
	"regexp"
	"strings"
)

type AdminServer struct {
	*BaseServer
}

func NewAdminServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *AdminServer {
	return &AdminServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
	}
}

func (s *AdminServer) setupRoutes() {
	s.setupHealthCheck()

	// Admin API routes
	api := s.router.Group("/api/v1")
	{
		// Gateway management
		gateways := api.Group("/gateways")
		{
			gateways.POST("", s.createGateway)
			gateways.GET("", s.listGateways)
			gateways.GET("/:gateway_id", s.getGatewayHandler)
			gateways.PUT("/:gateway_id", s.updateGateway)
			gateways.DELETE("/:gateway_id", s.deleteGateway)

			// API Key management
			apiKeys := gateways.Group("/:gateway_id/api-keys")
			{
				apiKeys.POST("", s.createAPIKey)
				apiKeys.GET("", s.listAPIKeys)
				apiKeys.GET("/:key_id", s.getAPIKeyHandler)
				apiKeys.DELETE("/:key_id", s.revokeAPIKey)
			}

			// Forwarding rules management
			rules := gateways.Group("/:gateway_id/rules")
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
	// Initialize cache with gateways list
	if err := s.updateGatewaysList(&gin.Context{}); err != nil {
		s.logger.WithError(err).Error("Failed to initialize gateways cache")
	}

	s.setupRoutes()
	return s.router.Run(fmt.Sprintf(":%d", s.config.AdminPort))
}

// Gateway Management
func (s *AdminServer) createGateway(c *gin.Context) {
	var req types.CreateGatewayRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Log the request
	s.logger.WithFields(logrus.Fields{
		"name":      req.Name,
		"subdomain": req.Subdomain,
		"tier":      req.Tier,
	}).Info("Creating gateway")

	// Create gateway with explicit ID and properly initialized RequiredPlugins
	gatewayID := uuid.NewString()
	s.logger.WithField("gateway_id", gatewayID).Info("Generated gateway ID")

	// Initialize with empty JSON object for RequiredPlugins
	emptyPlugins := make(map[string]types.PluginConfig)
	requiredPluginsJSON, err := json.Marshal(emptyPlugins)
	if err != nil {
		s.logger.WithError(err).Error("Failed to initialize required plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize gateway configuration"})
		return
	}

	gateway := &database.Gateway{
		ID:              gatewayID,
		Name:            req.Name,
		Subdomain:       req.Subdomain,
		ApiKey:          generateAPIKey(),
		Status:          "active",
		Tier:            req.Tier,
		EnabledPlugins:  database.StringArray(req.EnabledPlugins),
		RequiredPlugins: database.JSONMap(requiredPluginsJSON), // Use properly marshaled JSON
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Add validation for required fields
	if gateway.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Name is required"})
		return
	}

	if gateway.Subdomain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Subdomain is required"})
		return
	}

	if gateway.Tier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tier is required"})
		return
	}

	// Store in database
	if err := s.repo.CreateGateway(c, gateway); err != nil {
		s.logger.WithError(err).Error("Failed to create gateway in database")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create gateway"})
		return
	}

	s.logger.WithField("gateway_id", gateway.ID).Info("Gateway created successfully")

	// Cache gateway data
	gatewayKey := fmt.Sprintf("gateway:%s", gateway.ID)
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gateway.ID,
		"cache_key":  gatewayKey,
	}).Info("Caching gateway data")

	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal gateway")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cache gateway data"})
		return
	}

	if err := s.cache.Set(c, gatewayKey, string(gatewayJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to cache gateway data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cache gateway data"})
		return
	}

	// Cache subdomain mapping
	subdomainKey := fmt.Sprintf("subdomain:%s", gateway.Subdomain)
	s.logger.WithFields(logrus.Fields{
		"subdomain":  gateway.Subdomain,
		"gateway_id": gateway.ID,
		"cache_key":  subdomainKey,
	}).Info("Caching subdomain mapping")

	if err := s.cache.Set(c, subdomainKey, gateway.ID, 0); err != nil {
		s.logger.WithError(err).Error("Failed to cache subdomain mapping")
		// Try to clean up gateway cache
		_ = s.cache.Delete(c, gatewayKey)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cache gateway data"})
		return
	}

	// Initialize empty rules cache
	rulesKey := fmt.Sprintf("rules:%s", gateway.ID)
	if err := s.cache.Set(c, rulesKey, "[]", 0); err != nil {
		s.logger.WithError(err).Error("Failed to initialize rules cache")
		// Try to clean up other cache entries
		_ = s.cache.Delete(c, gatewayKey)
		_ = s.cache.Delete(c, subdomainKey)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize gateway cache"})
		return
	}

	// Update gateways list in cache
	if err := s.updateGatewaysList(c); err != nil {
		s.logger.WithError(err).Error("Failed to update gateways list")
		// Don't fail the request if cache update fails
	}

	c.JSON(http.StatusCreated, gateway)
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
		go func(g database.Gateway) {
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
		dbGateway.EnabledPlugins = database.StringArray(req.EnabledPlugins)
	}
	if req.RequiredPlugins != nil {
		// First convert existing plugins to map
		existingPlugins, err := dbGateway.RequiredPlugins.ToPluginConfigMap()
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert existing required plugins")
			existingPlugins = make(map[string]types.PluginConfig)
		}

		// Merge new plugins with existing ones
		for name, config := range req.RequiredPlugins {
			existingPlugins[name] = config
		}

		// Convert back to JSONMap
		jsonMap, err := database.PluginConfigMapToJSONMap(existingPlugins)
		if err != nil {
			s.logger.WithError(err).Error("Failed to convert required plugins")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process gateway configuration"})
			return
		}
		dbGateway.RequiredPlugins = jsonMap
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
		CreatedAt:       dbGateway.CreatedAt,
		UpdatedAt:       dbGateway.UpdatedAt,
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

	// Add validation for gateway ID
	if err := validateGatewayID(gatewayID); err != nil {
		s.logger.WithError(err).WithField("gateway_id", gatewayID).Error("Invalid gateway ID")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify gateway exists
	dbGateway, err := s.repo.GetGateway(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway")
		c.JSON(http.StatusNotFound, gin.H{"error": "Gateway not found"})
		return
	}

	if dbGateway.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Gateway is not active"})
		return
	}

	var req types.CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		s.logger.WithError(err).Error("Failed to bind request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := &database.APIKey{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Key:       utils.GenerateApiKey(),
		GatewayID: gatewayID,
		Status:    "active",
		CreatedAt: time.Now(),
		ExpiresAt: req.ExpiresAt,
	}

	// Store in database
	if err := s.repo.CreateAPIKey(c, apiKey); err != nil {
		s.logger.WithError(err).Error("Failed to create API key")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Store in cache for fast access
	key := fmt.Sprintf("apikey:%s:%s", gatewayID, apiKey.ID)
	apiKeyJSON, err := json.Marshal(apiKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal API key")
		return
	}
	if err := s.cache.Set(c, key, string(apiKeyJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to cache API key")
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

	// Initialize headers array with empty JSON array
	headersJSON, err := json.Marshal([]string{})
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal empty headers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process headers"})
		return
	}

	var headers database.StringArray
	if err := headers.Scan(headersJSON); err != nil {
		s.logger.WithError(err).Error("Failed to initialize headers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process headers"})
		return
	}

	// Add headers if provided
	if len(req.Headers) > 0 {
		var headersList []string
		for k, v := range req.Headers {
			headersList = append(headersList, fmt.Sprintf("%s:%s", k, v))
		}
		headersJSON, err := json.Marshal(headersList)
		if err != nil {
			s.logger.WithError(err).Error("Failed to marshal headers")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process headers"})
			return
		}
		if err := headers.Scan(headersJSON); err != nil {
			s.logger.WithError(err).Error("Failed to scan headers")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process headers"})
			return
		}
	}

	// Convert plugin chain to JSON array
	pluginChainJSON, err := json.Marshal(req.PluginChain)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal plugin chain")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	var pluginChainArray database.JSONArray
	if err := pluginChainArray.Scan(pluginChainJSON); err != nil {
		s.logger.WithError(err).Error("Failed to convert plugin chain to database format")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	rule := &database.ForwardingRule{
		ID:            uuid.New().String(),
		GatewayID:     gatewayID,
		Path:          req.Path,
		Target:        req.Target,
		Methods:       database.StringArray(methods),
		Headers:       headers,
		StripPath:     req.StripPath != nil && *req.StripPath,
		PreserveHost:  req.PreserveHost != nil && *req.PreserveHost,
		RetryAttempts: defaultIfNil(req.RetryAttempts, 0),
		PluginChain:   pluginChainArray,
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create rule: %v", err)})
		return
	}

	s.logger.Info("Successfully stored rule in database")

	// Update rules cache
	if err := s.updateRulesCache(c, gatewayID); err != nil {
		s.logger.WithError(err).Error("Failed to update rules cache")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rules cache"})
		return
	}

	s.logger.Info("Successfully updated rules cache")

	// Convert plugin chain back to array for response
	var pluginChain []types.PluginConfig
	if err := json.Unmarshal(pluginChainJSON, &pluginChain); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal plugin chain for response")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process plugin configuration"})
		return
	}

	response := &types.ForwardingRule{
		ID:            rule.ID,
		GatewayID:     rule.GatewayID,
		Path:          rule.Path,
		Target:        rule.Target,
		Methods:       []string(rule.Methods),
		Headers:       []string(rule.Headers),
		StripPath:     rule.StripPath,
		PreserveHost:  rule.PreserveHost,
		RetryAttempts: rule.RetryAttempts,
		PluginChain:   pluginChain,
		Active:        rule.Active,
		Public:        rule.Public,
		CreatedAt:     rule.CreatedAt,
		UpdatedAt:     rule.UpdatedAt,
	}

	s.logger.WithFields(logrus.Fields{
		"response": response,
	}).Info("Sending response")

	c.JSON(http.StatusCreated, response)
}

func (s *AdminServer) listForwardingRules(c *gin.Context) {
	gatewayID := c.Param("gateway_id")

	// Get rules from database
	rules, err := s.repo.ListRules(c, gatewayID)
	if err != nil {
		s.logger.WithError(err).Error("Failed to list rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rules"})
		return
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
	rules, err := s.getForwardingRules(c, gatewayID)
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
		var headers []string
		for k, v := range req.Headers {
			headers = append(headers, fmt.Sprintf("%s:%s", k, v))
		}
		rule.Headers = headers
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
	if err := s.saveForwardingRules(c, gatewayID, rules); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	c.JSON(http.StatusOK, rule)
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

func (s *AdminServer) updateRulesCache(c *gin.Context, gatewayID string) error {
	s.logger.WithFields(logrus.Fields{
		"gateway_id": gatewayID,
	}).Info("Updating rules cache")

	// Get rules from database
	rules, err := s.repo.ListRules(c, gatewayID)
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
			if err := json.Unmarshal([]byte(rule.PluginChain), &pluginChain); err != nil {
				s.logger.WithError(err).Error("Failed to unmarshal plugin chain")
				return err
			}
		}

		apiRules[i] = types.ForwardingRule{
			ID:            rule.ID,
			GatewayID:     rule.GatewayID,
			Path:          rule.Path,
			Target:        rule.Target,
			Methods:       []string(rule.Methods),
			Headers:       []string(rule.Headers),
			StripPath:     rule.StripPath,
			PreserveHost:  rule.PreserveHost,
			RetryAttempts: rule.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        rule.Active,
			Public:        rule.Public,
			CreatedAt:     rule.CreatedAt,
			UpdatedAt:     rule.UpdatedAt,
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
	if err := s.cache.Set(c, rulesKey, string(rulesJSON), 0); err != nil {
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
		CreatedAt:       dbGateway.CreatedAt,
		UpdatedAt:       dbGateway.UpdatedAt,
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

func (s *AdminServer) updateGatewayCache(ctx context.Context, dbGateway *database.Gateway) error {
	if err := validateGatewayID(dbGateway.ID); err != nil {
		return fmt.Errorf("invalid gateway ID: %w", err)
	}

	gateway, err := s.convertDBGatewayToAPI(dbGateway)
	if err != nil {
		return fmt.Errorf("failed to convert gateway: %w", err)
	}

	// Store in cache
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}

	key := fmt.Sprintf("gateway:%s", dbGateway.ID)
	if err := s.cache.Set(ctx, key, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	return nil
}

func (s *AdminServer) convertDBGatewayToAPI(dbGateway *database.Gateway) (*types.Gateway, error) {
	// Add validation for gateway ID
	if err := validateGatewayID(dbGateway.ID); err != nil {
		return nil, fmt.Errorf("invalid gateway data: %w", err)
	}

	// Initialize RequiredPlugins if it's nil or invalid
	if len(dbGateway.RequiredPlugins) == 0 ||
		!json.Valid([]byte(dbGateway.RequiredPlugins)) ||
		string(dbGateway.RequiredPlugins) == "\u0000\u0002" ||
		string(dbGateway.RequiredPlugins) == "}}" {

		s.logger.WithFields(logrus.Fields{
			"gateway_id": dbGateway.ID,
			"plugins":    string(dbGateway.RequiredPlugins),
		}).Warn("Invalid or empty RequiredPlugins, resetting to empty object")

		// Create empty plugins map and marshal to JSON
		emptyPlugins := make(map[string]types.PluginConfig)
		pluginsJSON, err := json.Marshal(emptyPlugins)
		if err != nil {
			s.logger.WithError(err).Error("Failed to marshal empty plugins")
			pluginsJSON = []byte("{}")
		}
		dbGateway.RequiredPlugins = database.JSONMap(pluginsJSON)
	}

	requiredPlugins, err := dbGateway.RequiredPlugins.ToPluginConfigMap()
	if err != nil {
		s.logger.WithError(err).WithFields(logrus.Fields{
			"gateway_id": dbGateway.ID,
			"plugins":    string(dbGateway.RequiredPlugins),
		}).Error("Failed to convert required plugins")
		// Reset to empty object on error
		dbGateway.RequiredPlugins = database.JSONMap(`{}`)
		requiredPlugins = make(map[string]types.PluginConfig)
	}

	return &types.Gateway{
		ID:              dbGateway.ID,
		Name:            dbGateway.Name,
		Subdomain:       dbGateway.Subdomain,
		ApiKey:          dbGateway.ApiKey,
		Status:          dbGateway.Status,
		Tier:            dbGateway.Tier,
		CreatedAt:       dbGateway.CreatedAt,
		UpdatedAt:       dbGateway.UpdatedAt,
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
			dbGateway.RequiredPlugins = database.JSONMap(`{}`)
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

// generateAPIKey creates a new random API key
func generateAPIKey() string {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	// Encode as base64 and remove padding
	return strings.TrimRight(base64.URLEncoding.EncodeToString(bytes), "=")
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
