package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"ai-gateway-ce/internal/middleware"
	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/common"
	"ai-gateway-ce/pkg/config"
	"ai-gateway-ce/pkg/database"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/pluginiface"
	"ai-gateway-ce/pkg/plugins"
	"ai-gateway-ce/pkg/types"
)

type ProxyServer struct {
	*BaseServer
	repo          *database.Repository
	pluginManager *plugins.Manager
	gatewayCache  *common.TTLMap
	rulesCache    *common.TTLMap
	pluginCache   *common.TTLMap
	skipAuthCheck bool
	httpClient    *http.Client
	loadBalancer  LoadBalancer
}

// Cache TTLs
const (
	GatewayCacheTTL = 1 * time.Hour
	RulesCacheTTL   = 5 * time.Minute
	PluginCacheTTL  = 30 * time.Minute
)

func NewProxyServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger, skipAuthCheck bool, extraPlugins ...pluginiface.Plugin) *ProxyServer {
	// Initialize plugins
	plugins.InitializePlugins(cache, logger)
	manager := plugins.GetManager()

	// Register extra plugins
	for _, plugin := range extraPlugins {
		manager.RegisterPlugin(plugin)
	}

	// Create TTL maps
	gatewayCache := cache.CreateTTLMap("gateway", GatewayCacheTTL)
	rulesCache := cache.CreateTTLMap("rules", RulesCacheTTL)
	pluginCache := cache.CreateTTLMap("plugin", PluginCacheTTL)

	s := &ProxyServer{
		BaseServer:    NewBaseServer(config, cache, repo, logger),
		repo:          repo,
		pluginManager: manager,
		gatewayCache:  gatewayCache,
		rulesCache:    rulesCache,
		pluginCache:   pluginCache,
		skipAuthCheck: skipAuthCheck,
		httpClient:    &http.Client{},
		loadBalancer:  NewLoadBalancer(cache, logger),
	}

	// Subscribe to gateway events
	go s.subscribeToEvents()

	return s
}

func (s *ProxyServer) GetRouter() *gin.Engine {
	return s.router
}

func (s *ProxyServer) Run() error {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	// Create a new router group for all routes
	baseGroup := s.router.Group("")

	// Add system routes handler to the base group
	baseGroup.Use(func(c *gin.Context) {
		path := c.Request.URL.Path

		// Handle system routes
		switch path {
		case "/__/health", "/health":
			c.JSON(http.StatusOK, gin.H{
				"status": "ok",
				"time":   time.Now().Format(time.RFC3339),
			})
			c.Abort()
			return
		case "/__/ping":
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
			c.Abort()
			return
		}

		// Continue to next middleware for non-system routes
		c.Next()
	})

	// Create a new group for non-system routes
	apiGroup := baseGroup.Group("")

	// Add gateway identification middleware and auth middleware to the API group
	gatewayMiddleware := middleware.NewGatewayMiddleware(s.logger, s.cache, s.repo, s.config.Server.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.logger, s.repo)

	apiGroup.Use(gatewayMiddleware.IdentifyGateway())
	apiGroup.Use(func(c *gin.Context) {
		if !s.skipAuthCheck && !isPublicRoute(c, s.cache) {
			authMiddleware.ValidateAPIKey()(c)
		}
	})

	// Add catch-all route for proxying to the API group
	apiGroup.Any("/*path", s.HandleForward)

	// Start the server
	return s.router.Run(fmt.Sprintf(":%d", s.config.Server.ProxyPort))
}

func (s *ProxyServer) HandleForward(c *gin.Context) {
	// Add logger to context
	ctx := context.WithValue(c.Request.Context(), "logger", s.logger)

	path := c.Request.URL.Path
	method := c.Request.Method

	// Get gateway ID from context
	gatewayID, exists := c.Get(middleware.GatewayContextKey)
	if !exists {
		s.logger.Error("Gateway ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Get metadata from gin context
	var metadata map[string]interface{}
	if md, exists := c.Get("metadata"); exists {
		if m, ok := md.(map[string]interface{}); ok {
			metadata = m
		}
	}

	if metadata == nil {
		metadata = make(map[string]interface{})
		if apiKey, exists := c.Get("api_key"); exists && apiKey != nil {
			metadata["api_key"] = apiKey
		}
	}

	// Create the RequestContext
	reqCtx := &types.RequestContext{
		Context:   ctx,
		GatewayID: gatewayID.(string),
		Headers:   make(map[string][]string),
		Method:    method,
		Path:      path,
		Query:     c.Request.URL.Query(),
		Metadata:  metadata,
	}
	// Read the request body
	bodyData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		s.logger.WithError(err).Error("Failed to read request body")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Set the body in the request context
	reqCtx.Body = bodyData

	// Restore the request body for later use
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyData))

	// Copy request headers
	for key, values := range c.Request.Header {
		reqCtx.Headers[key] = values
	}

	// Create the ResponseContext
	respCtx := &types.ResponseContext{
		Context:   ctx,
		GatewayID: gatewayID.(string),
		Headers:   make(map[string][]string),
		Metadata:  make(map[string]interface{}),
	}

	// Get gateway data with plugins
	gatewayData, err := s.getGatewayData(ctx, gatewayID.(string))
	s.logger.WithFields(logrus.Fields{
		"gatewayData": gatewayData,
	}).Debug("Gateway data")
	reqCtx.Metadata["gateway_data"] = gatewayData

	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range gatewayData.Rules {
		s.logger.WithFields(logrus.Fields{
			"rule": rule,
		}).Debug("Rule")
		if !rule.Active {
			continue
		}

		// Check if method is allowed
		methodAllowed := false
		for _, m := range rule.Methods {
			if m == method {
				methodAllowed = true
				break
			}
		}

		if !methodAllowed {
			continue
		}

		// Check if path matches
		if strings.HasPrefix(path, rule.Path) {
			// Convert the rule to models.ForwardingRule
			modelRule := types.ForwardingRule{
				ID:                    rule.ID,
				GatewayID:             rule.GatewayID,
				Path:                  rule.Path,
				Targets:               models.TargetsJSON(rule.Targets),
				Credentials:           rule.Credentials,
				FallbackTargets:       models.TargetsJSON(rule.FallbackTargets),
				FallbackCredentials:   rule.FallbackCredentials,
				Methods:               models.MethodsJSON(rule.Methods),
				Headers:               models.HeadersJSON(rule.Headers),
				StripPath:             rule.StripPath,
				PreserveHost:          rule.PreserveHost,
				RetryAttempts:         rule.RetryAttempts,
				PluginChain:           rule.PluginChain,
				Active:                rule.Active,
				Public:                rule.Public,
				CreatedAt:             time.Now().Format(time.RFC3339),
				UpdatedAt:             time.Now().Format(time.RFC3339),
				LoadBalancingStrategy: rule.LoadBalancingStrategy,
			}
			matchingRule = &modelRule
			break
		}
	}

	if matchingRule == nil {
		s.logger.WithFields(logrus.Fields{
			"path":   path,
			"method": method,
		}).Debug("No matching rule found")
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found"})
		return
	}

	// Configure plugins for this request
	if err := s.configurePlugins(gatewayData.Gateway, matchingRule); err != nil {
		s.logger.WithError(err).Error("Failed to configure plugins")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to configure plugins"})
		return
	}

	// Execute pre-request plugins
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PreRequest, gatewayID.(string), matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}
	// Forward the request
	response, err := s.forwardRequest(reqCtx, matchingRule)
	if err != nil {
		s.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
	}

	// Copy response to response context
	respCtx.StatusCode = response.StatusCode
	respCtx.Body = response.Body
	for k, v := range response.Headers {
		respCtx.Headers[k] = v
	}

	// If it's an error response (4xx or 5xx), return the original error response
	if response.StatusCode >= 400 {
		// Parse the error response
		var errorResponse map[string]interface{}
		if err := json.Unmarshal(response.Body, &errorResponse); err != nil {
			// If we can't parse the error, return a generic error
			c.JSON(response.StatusCode, gin.H{"error": "Upstream service error"})
			return
		}

		// Copy all headers from response context to client response
		for k, values := range respCtx.Headers {
			for _, v := range values {
				c.Header(k, v)
			}
		}

		// Return the original error response
		c.JSON(response.StatusCode, errorResponse)
		return
	}

	// Execute pre-response plugins
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PreResponse, gatewayID.(string), matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}

	// Execute post-response plugins
	if _, err := s.pluginManager.ExecuteStage(ctx, types.PostResponse, gatewayID.(string), matchingRule.ID, reqCtx, respCtx); err != nil {
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Copy headers from response context
			s.logger.WithFields(logrus.Fields{
				"headers": respCtx.Headers,
			}).Debug("Plugin response headers")

			for k, values := range respCtx.Headers {
				for _, v := range values {
					c.Header(k, v)
				}
			}
			c.JSON(pluginErr.StatusCode, gin.H{
				"error":       pluginErr.Message,
				"retry_after": respCtx.Metadata["retry_after"],
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}

	// Copy all headers from response context to client response
	for k, values := range respCtx.Headers {
		for _, v := range values {
			c.Header(k, v)
		}
	}

	// Write the response body
	c.Data(respCtx.StatusCode, "application/json", respCtx.Body)
}

// Helper function to check if a route is public
func isPublicRoute(c *gin.Context, cache *cache.Cache) bool {
	gatewayID, exists := c.Get(middleware.GatewayContextKey)
	if !exists {
		return false
	}

	// Get rules for gateway
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := cache.Get(c, rulesKey)
	if err != nil {
		return false
	}

	var rules []models.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return false
	}

	// Check if any matching rule is public
	path := c.Request.URL.Path
	for _, rule := range rules {
		if rule.Active && strings.HasPrefix(path, rule.Path) {
			return rule.Public
		}
	}

	return false
}

func (s *ProxyServer) configurePlugins(gateway *types.Gateway, rule *types.ForwardingRule) error {
	// Configure gateway-level plugins
	gatewayChains := s.convertGatewayPlugins(gateway)
	s.logger.WithFields(logrus.Fields{
		"gatewayChains": gatewayChains,
	}).Debug("Gateway chains")

	if err := s.pluginManager.SetPluginChain(types.GatewayLevel, gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}

	if rule != nil && len(rule.PluginChain) > 0 {
		s.logger.WithFields(logrus.Fields{
			"ruleID":  rule.ID,
			"plugins": rule.PluginChain,
		}).Debug("Rule plugins")

		if err := s.pluginManager.SetPluginChain(types.RuleLevel, rule.ID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}

	return nil
}

func (s *ProxyServer) getGatewayData(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	logger := ctx.Value("logger").(*logrus.Logger)

	// 1. Try memory cache first
	if cached, ok := s.gatewayCache.Get(gatewayID); ok {
		logger.WithField("fromCache", "memory").Debug("Gateway data found in memory cache")
		return cached.(*types.GatewayData), nil
	}

	// 2. Try Redis cache
	gatewayData, err := s.getGatewayDataFromRedis(ctx, gatewayID)
	if err == nil {
		logger.WithFields(logrus.Fields{
			"gatewayID":  gatewayID,
			"rulesCount": len(gatewayData.Rules),
			"fromCache":  "redis",
		}).Debug("Gateway data found in Redis cache")

		// Store in memory cache
		s.gatewayCache.Set(gatewayID, gatewayData)
		return gatewayData, nil
	}
	logger.WithError(err).Debug("Failed to get gateway data from Redis")

	// 3. Fallback to database
	return s.getGatewayDataFromDB(ctx, gatewayID)
}

func (s *ProxyServer) getGatewayDataFromRedis(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	// Get gateway from Redis
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	gatewayJSON, err := s.cache.Get(ctx, gatewayKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from Redis: %w", err)
	}

	var gateway *models.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gateway from Redis: %w", err)
	}

	// Get rules from Redis
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(ctx, rulesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from Redis: %w", err)
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rules from Redis: %w", err)
	}

	return &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   rules,
	}, nil
}

func (s *ProxyServer) getGatewayDataFromDB(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	logger := ctx.Value("logger").(*logrus.Logger)

	// Get gateway from database
	gateway, err := s.repo.GetGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway from database: %w", err)
	}

	// Get rules from database
	rules, err := s.repo.ListRules(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from database: %w", err)
	}

	// Convert models to types
	gatewayData := &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   convertModelToTypesRules(rules),
	}

	// Cache the results
	if err := s.cacheGatewayData(ctx, gatewayID, gateway, rules); err != nil {
		logger.WithError(err).Warn("Failed to cache gateway data")
	}

	logger.WithFields(logrus.Fields{
		"gatewayID":       gatewayID,
		"requiredPlugins": gateway.RequiredPlugins,
		"rulesCount":      len(rules),
		"fromCache":       "database",
	}).Debug("Loaded gateway data from database")

	return gatewayData, nil
}

func (s *ProxyServer) cacheGatewayData(ctx context.Context, gatewayID string, gateway *models.Gateway, rules []models.ForwardingRule) error {
	// Cache gateway
	gatewayJSON, err := json.Marshal(gateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}
	gatewayKey := fmt.Sprintf("gateway:%s", gatewayID)
	if err := s.cache.Set(ctx, gatewayKey, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	// Cache rules
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return fmt.Errorf("failed to marshal rules: %w", err)
	}
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Set(ctx, rulesKey, string(rulesJSON), 0); err != nil {
		return fmt.Errorf("failed to cache rules: %w", err)
	}

	// Cache in memory
	gatewayData := &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   convertModelToTypesRules(rules),
	}
	s.gatewayCache.Set(gatewayID, gatewayData)

	return nil
}

// Helper functions to convert between models and types
func convertModelToTypesGateway(g *models.Gateway) *types.Gateway {
	requiredPlugins := []types.PluginConfig{}

	// Convert required plugins
	for _, pluginConfig := range g.RequiredPlugins {
		requiredPlugins = append(requiredPlugins, pluginConfig)
	}

	return &types.Gateway{
		ID:              g.ID,
		Name:            g.Name,
		Subdomain:       g.Subdomain,
		Type:            g.Type,
		Status:          g.Status,
		RequiredPlugins: requiredPlugins,
		Settings:        convertModelToTypesSettings(g.Settings),
	}
}

// Helper function to convert GatewaySettings
func convertModelToTypesSettings(s models.GatewaySettings) types.GatewaySettings {
	traffic := make([]types.GatewayTraffic, len(s.Traffic))
	for i, t := range s.Traffic {
		traffic[i] = types.GatewayTraffic{
			Provider: t.Provider,
			Weight:   t.Weight,
		}
	}

	providers := make([]types.GatewayProvider, len(s.Providers))
	for i, p := range s.Providers {
		providers[i] = types.GatewayProvider{
			Name:                p.Name,
			Path:                p.Path,
			StripPath:           p.StripPath,
			Credentials:         (*types.Credentials)(&p.Credentials),
			FallbackProvider:    p.FallbackProvider,
			FallbackCredentials: (*types.Credentials)(&p.FallbackCredentials),
			PluginChain:         convertPluginChain(p.PluginChain),
			AllowedModels:       p.AllowedModels,
			FallbackModelMap:    p.FallbackModelMap,
		}
	}

	return types.GatewaySettings{
		Traffic:   traffic,
		Providers: providers,
	}
}

func convertModelToTypesRules(rules []models.ForwardingRule) []types.ForwardingRule {
	var result []types.ForwardingRule
	for _, r := range rules {
		// Convert pq.StringArray to map[string]string
		headers := make(map[string]string)
		for _, h := range r.Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		// The plugin chain is already []types.PluginConfig, no need for wrapper
		result = append(result, types.ForwardingRule{
			ID:                    r.ID,
			GatewayID:             r.GatewayID,
			Path:                  r.Path,
			Targets:               r.Targets,
			Credentials:           r.Credentials.ToCredentials(),
			FallbackTargets:       r.FallbackTargets,
			FallbackCredentials:   r.FallbackCredentials.ToCredentials(),
			Methods:               r.Methods,
			Headers:               headers,
			StripPath:             r.StripPath,
			PreserveHost:          r.PreserveHost,
			RetryAttempts:         r.RetryAttempts,
			PluginChain:           r.PluginChain,
			Active:                r.Active,
			Public:                r.Public,
			CreatedAt:             r.CreatedAt.Format(time.RFC3339),
			UpdatedAt:             r.UpdatedAt.Format(time.RFC3339),
			LoadBalancingStrategy: r.LoadBalancingStrategy,
		})
	}
	return result
}

// Helper function to make a request to a specific target
func (s *ProxyServer) makeTargetRequest(client *fasthttp.Client, req *fasthttp.Request, resp *fasthttp.Response, reqCtx *types.RequestContext, rule *types.ForwardingRule, targetURL string) (*fasthttp.Response, error) {
	// Get gateway data from context
	gatewayData, ok := reqCtx.Metadata["gateway_data"].(*types.GatewayData)
	if !ok {
		s.logger.Error("Gateway data not found in request context")
		return nil, fmt.Errorf("gateway data not found")
	}

	// For model gateways, validate the requested model
	if gatewayData.Gateway.Type == "models" {
		// Parse request body to get model
		var requestBody map[string]interface{}
		if err := json.Unmarshal(reqCtx.Body, &requestBody); err != nil {
			s.logger.WithError(err).Error("Failed to parse request body")
			return nil, fmt.Errorf("invalid request body")
		}

		// Check if model is specified
		model, ok := requestBody["model"].(string)
		if !ok {
			s.logger.Error("Model not specified in request")
			return nil, fmt.Errorf("model not specified")
		}

		// Find the provider and check allowed models
		for _, provider := range gatewayData.Gateway.Settings.Providers {
			if strings.Contains(targetURL, provider.Path) {
				// If AllowedModels is empty or not specified, all models are allowed
				if len(provider.AllowedModels) > 0 {
					modelAllowed := false
					for _, allowedModel := range provider.AllowedModels {
						if allowedModel == model {
							modelAllowed = true
							break
						}
					}
					if !modelAllowed {
						s.logger.WithField("model", model).Error("Model not allowed")
						return nil, fmt.Errorf("model %s not allowed", model)
					}
				}
				break
			}
		}
	}

	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL // Default to HTTPS
	}

	// Build target URL
	var targetPath string
	if rule.StripPath {
		targetPath = strings.TrimPrefix(reqCtx.Path, rule.Path)
		targetURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(targetPath, "/")
		targetURL = strings.TrimSuffix(targetURL, "/")
	} else {
		targetURL = strings.TrimRight(targetURL, "/") + reqCtx.Path
	}

	// Add query parameters if any
	if len(reqCtx.Query) > 0 {
		targetURL += "?" + reqCtx.Query.Encode()
	}

	// Set request details
	req.SetRequestURI(targetURL)
	req.Header.SetMethod(reqCtx.Method)

	// Copy headers from original request
	for k, v := range reqCtx.Headers {
		for _, val := range v {
			req.Header.Add(k, val)
		}
	}

	// Apply authentication if configured and not already set
	if rule.Credentials != nil {
		s.applyAuthentication(req, rule.Credentials, reqCtx.Body)
	} else {
		s.logger.Debug("No credentials found")
	}

	// Set body if present
	if len(reqCtx.Body) > 0 {
		req.SetBody(reqCtx.Body)
	}

	s.logger.WithFields(logrus.Fields{
		"headers": req.Header.String(),
		"url":     targetURL,
	}).Debug("Making request")

	// Make the request
	err := client.Do(req, resp)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	return resp, nil
}

// Helper function to find the fallback provider configuration
func (s *ProxyServer) findFallbackProvider(gatewayData *types.GatewayData, primaryProviderPath string) (*types.GatewayProvider, error) {
	for _, p := range gatewayData.Gateway.Settings.Providers {
		if p.Path == primaryProviderPath && p.FallbackProvider != "" {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("no fallback provider found for path %s", primaryProviderPath)
}

// Helper function to get the fallback URL with mapped endpoint
func (s *ProxyServer) getFallbackURL(provider *types.GatewayProvider, fallbackTarget string, originalPath string) (string, error) {
	// Load provider configuration
	providerConfig, err := config.LoadProviderConfig()
	if err != nil {
		return "", fmt.Errorf("failed to load provider config: %v", err)
	}

	// Extract endpoint type from original path
	endpointType := "chat"
	if strings.Contains(originalPath, "completions") {
		if strings.Contains(originalPath, "chat/completions") {
			endpointType = "chat"
		} else {
			endpointType = "completions"
		}
	} else if strings.Contains(originalPath, "embeddings") {
		endpointType = "embeddings"
	}

	// Find the target provider and map the endpoint
	var mappedPath string
	if providerCfg, ok := providerConfig.Providers[provider.FallbackProvider]; ok {
		if endpoint, ok := providerCfg.Endpoints[endpointType]; ok {
			mappedPath = endpoint
			s.logger.WithFields(logrus.Fields{
				"provider": provider.FallbackProvider,
				"endpoint": endpoint,
			}).Debug("Mapped fallback endpoint")
		}
	}

	if mappedPath == "" {
		return "", fmt.Errorf("no endpoint mapping found for %s", endpointType)
	}

	// Construct the full URL
	fallbackURL := fallbackTarget
	if !strings.HasPrefix(fallbackURL, "http://") && !strings.HasPrefix(fallbackURL, "https://") {
		fallbackURL = "https://" + fallbackURL
	}
	return strings.TrimRight(fallbackURL, "/") + mappedPath, nil
}

// Helper function to transform request body for fallback provider
func (s *ProxyServer) transformRequestForProvider(provider *types.GatewayProvider, requestData map[string]interface{}) ([]byte, error) {
	// Map model if mapping exists
	if model, ok := requestData["model"].(string); ok {
		if fallbackModel, exists := provider.FallbackModelMap[model]; exists {
			requestData["model"] = fallbackModel
		}
	}

	if provider.FallbackProvider == "anthropic" {
		requestData["max_tokens"] = 1024
		return json.Marshal(requestData)
	}

	// For other providers, just update the model and keep the same format
	return json.Marshal(requestData)
}

// Main fallback request function
func (s *ProxyServer) makeFallbackRequest(ctx context.Context, gatewayData *types.GatewayData, req *types.RequestContext, reqBody []byte) (*fasthttp.Response, error) {
	// Parse request body
	var requestData map[string]interface{}
	if err := json.Unmarshal(reqBody, &requestData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request body: %v", err)
	}

	// Extract primary provider path from the request path
	primaryProviderPath := "/"
	for _, provider := range gatewayData.Gateway.Settings.Providers {
		if strings.HasPrefix(req.Path, provider.Path) {
			primaryProviderPath = provider.Path
			break
		}
	}

	// Find the provider with fallback configuration
	provider, err := s.findFallbackProvider(gatewayData, primaryProviderPath)
	if err != nil {
		return nil, err
	}

	// Find the fallback rule and target
	var fallbackRule *types.ForwardingRule
	var fallbackTarget string
	for _, rule := range gatewayData.Rules {
		if rule.Path == provider.Path {
			fallbackRule = &rule
			if len(rule.FallbackTargets) > 0 {
				fallbackTarget = rule.FallbackTargets[0].URL
			}
			break
		}
	}
	if fallbackTarget == "" {
		return nil, fmt.Errorf("no fallback target found for provider %s", provider.Name)
	}

	// Get the fallback URL with mapped endpoint
	fallbackURL, err := s.getFallbackURL(provider, fallbackTarget, req.Path)
	if err != nil {
		return nil, err
	}

	// Transform request body for the fallback provider
	updatedReqBody, err := s.transformRequestForProvider(provider, requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to transform request body: %v", err)
	}

	s.logger.WithFields(logrus.Fields{
		"fallback_url": fallbackURL,
		"body":         string(updatedReqBody),
	}).Debug("Fallback request details")

	// Create and prepare the fallback request
	client := &fasthttp.Client{}
	httpReq := fasthttp.AcquireRequest()
	httpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(httpReq)

	// Set request details
	httpReq.SetRequestURI(fallbackURL)
	httpReq.Header.SetMethod(req.Method)
	httpReq.SetBody(updatedReqBody)

	// Copy headers from original request
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Apply authentication using the fallback credentials
	if fallbackRule != nil && fallbackRule.FallbackCredentials != nil {
		s.applyAuthentication(httpReq, fallbackRule.FallbackCredentials, updatedReqBody)
	} else if provider.FallbackCredentials != nil {
		s.applyAuthentication(httpReq, provider.FallbackCredentials, updatedReqBody)
	}

	// Make fallback request
	if err := client.Do(httpReq, httpResp); err != nil {
		return nil, fmt.Errorf("failed to make fallback request: %v", err)
	}

	return httpResp, nil
}

func (s *ProxyServer) forwardRequest(req *types.RequestContext, rule *types.ForwardingRule) (*types.ResponseContext, error) {
	client := &fasthttp.Client{}
	httpReq := fasthttp.AcquireRequest()
	httpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(httpReq)
	defer fasthttp.ReleaseResponse(httpResp)

	// Use the loadBalancer to select the target
	target, err := s.loadBalancer.SelectTarget(rule)
	if err != nil {
		return nil, fmt.Errorf("failed to select target: %w", err)
	}
	if target == nil {
		return nil, fmt.Errorf("no valid target found")
	}

	resp, err := s.makeTargetRequest(client, httpReq, httpResp, req, rule, target.URL)
	if err == nil && resp.StatusCode() < 400 {
		return s.createResponse(resp), nil
	}

	// If primary failed and we have fallback targets, try them
	if len(rule.FallbackTargets) > 0 {
		s.logger.WithFields(logrus.Fields{
			"primary_target": target.URL,
			"error":          err,
			"status_code":    resp != nil && resp.StatusCode() > 0,
		}).Info("Primary target failed, trying fallback")

		// Get gateway data from context
		gatewayData, ok := req.Metadata["gateway_data"].(*types.GatewayData)
		if !ok {
			return nil, fmt.Errorf("gateway data not found in request context")
		}

		// Try fallback request
		fallbackResp, fallbackErr := s.makeFallbackRequest(context.Background(), gatewayData, req, req.Body)
		if fallbackErr != nil {
			s.logger.WithFields(logrus.Fields{
				"error": fallbackErr,
			}).Warn("Fallback request failed")
		}
		if fallbackErr == nil && fallbackResp != nil && fallbackResp.StatusCode() < 400 {
			return s.createResponse(fallbackResp), nil
		}
	}

	// If we got here, return the original response if available, otherwise return the error
	if err != nil {
		return nil, err
	}
	if resp != nil {
		return s.createResponse(resp), nil
	}
	return nil, fmt.Errorf("all targets failed")
}

// Convert types.Credentials to CredentialsJSON
func (s *ProxyServer) applyAuthentication(req *fasthttp.Request, creds *types.Credentials, body []byte) {
	if creds == nil {
		s.logger.Debug("No credentials found")
		return
	}
	s.logger.WithFields(logrus.Fields{
		"creds": creds,
	}).Debug("Applying authentication")
	// Header-based auth
	if creds.HeaderName != "" && creds.HeaderValue != "" {
		s.logger.WithFields(logrus.Fields{
			"header_name": creds.HeaderName,
			// Don't log the actual value for security
			"has_value": creds.HeaderValue != "",
		}).Debug("Setting auth header")

		// Set the auth header
		req.Header.Set(creds.HeaderName, creds.HeaderValue)
	}

	// Parameter-based auth
	if creds.ParamName != "" && creds.ParamValue != "" {
		if creds.ParamLocation == "query" {
			uri := req.URI()
			args := uri.QueryArgs()
			args.Set(creds.ParamName, creds.ParamValue)
		} else if creds.ParamLocation == "body" && len(body) > 0 {
			// Parse JSON body
			var jsonBody map[string]interface{}
			if err := json.Unmarshal(body, &jsonBody); err != nil {
				s.logger.WithError(err).Error("Failed to parse request body")
				return
			}

			// Add auth parameter
			jsonBody[creds.ParamName] = creds.ParamValue

			// Rewrite body
			newBody, err := json.Marshal(jsonBody)
			if err != nil {
				s.logger.WithError(err).Error("Failed to marshal request body")
				return
			}

			req.SetBody(newBody)
		}
	}
}

// Helper function to create ResponseContext from fasthttp.Response
func (s *ProxyServer) createResponse(resp *fasthttp.Response) *types.ResponseContext {
	response := &types.ResponseContext{
		StatusCode: resp.StatusCode(),
		Headers:    make(map[string][]string),
		Body:       resp.Body(),
	}

	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		v := string(value)
		if response.Headers[k] == nil {
			response.Headers[k] = make([]string, 0)
		}
		response.Headers[k] = append(response.Headers[k], v)
	})

	return response
}

// Add getter for plugin manager
func (s *ProxyServer) PluginManager() *plugins.Manager {
	return s.pluginManager
}

func (s *ProxyServer) convertGatewayPlugins(gateway *types.Gateway) []types.PluginConfig {
	var chains []types.PluginConfig
	for _, config := range gateway.RequiredPlugins {
		if config.Enabled {
			// Get the plugin to check its stages
			plugin := s.pluginManager.GetPlugin(config.Name)
			if plugin == nil {
				s.logger.WithField("plugin", config.Name).Error("Plugin not found")
				continue
			}

			// Check if this is a fixed-stage plugin
			supportedStages := plugin.Stages()
			if len(supportedStages) > 0 {
				// For fixed-stage plugins, just add the config without a stage
				// The stage will be set when executing based on the plugin's supported stages
				pluginConfig := config
				pluginConfig.Level = types.GatewayLevel
				chains = append(chains, pluginConfig)
			} else {
				// For user-configured plugins, the stage must be set in the config
				if config.Stage == "" {
					s.logger.WithField("plugin", config.Name).Error("Stage not configured for plugin")
					continue
				}
				pluginConfig := config
				pluginConfig.Level = types.GatewayLevel
				chains = append(chains, pluginConfig)
			}
		}
	}
	return chains
}

// InvalidateGatewayCache removes the gateway data from both memory and Redis cache
func (s *ProxyServer) InvalidateGatewayCache(ctx context.Context, gatewayID string) error {
	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
	}).Debug("Invalidating gateway cache")

	// Remove from memory cache
	s.gatewayCache.Delete(gatewayID)

	// Remove from Redis cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if err := s.cache.Delete(ctx, rulesKey); err != nil {
		s.logger.WithError(err).Warn("Failed to delete rules from Redis cache")
	}

	return nil
}

func (s *ProxyServer) subscribeToEvents() {
	// Get Redis client from cache
	rdb := s.cache.Client()
	pubsub := rdb.Subscribe(context.Background(), "gateway_events")
	defer pubsub.Close()

	// Listen for messages
	ch := pubsub.Channel()
	for msg := range ch {
		var event map[string]string
		if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal event")
			continue
		}

		if event["type"] == "cache_invalidation" {
			gatewayID := event["gatewayID"]
			if err := s.InvalidateGatewayCache(context.Background(), gatewayID); err != nil {
				s.logger.WithError(err).Error("Failed to invalidate gateway cache")
			}
		}
	}
}

// Helper function to convert string slice to PluginConfig slice
func convertPluginChain(chain []string) []types.PluginConfig {
	configs := make([]types.PluginConfig, len(chain))
	for i, name := range chain {
		configs[i] = types.PluginConfig{
			Name:    name,
			Enabled: true,
		}
	}
	return configs
}
