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
	"ai-gateway-ce/pkg/database"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/plugins"
	"ai-gateway-ce/pkg/types"
)

type ProxyServer struct {
	*BaseServer
	repo          *database.Repository
	pluginFactory *plugins.PluginFactory
	pluginManager *plugins.Manager
	gatewayCache  *common.TTLMap
	rulesCache    *common.TTLMap
	pluginCache   *common.TTLMap
}

// Cache TTLs
const (
	GatewayCacheTTL = 1 * time.Hour
	RulesCacheTTL   = 5 * time.Minute
	PluginCacheTTL  = 30 * time.Minute
)

func NewProxyServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *ProxyServer {
	// Create TTL maps
	gatewayCache := cache.CreateTTLMap("gateway", GatewayCacheTTL)
	rulesCache := cache.CreateTTLMap("rules", RulesCacheTTL)
	pluginCache := cache.CreateTTLMap("plugin", PluginCacheTTL)

	// Create plugin factory and manager
	pluginFactory := plugins.NewPluginFactory(cache, logger)
	manager := plugins.NewManager(pluginFactory)

	// Register available plugins
	availablePlugins := []string{"rate_limiter", "external_validator"}
	for _, pluginName := range availablePlugins {
		if err := manager.RegisterPlugin(pluginName); err != nil {
			logger.Fatalf("Failed to register plugin %s: %v", pluginName, err)
		}
	}

	s := &ProxyServer{
		BaseServer:    NewBaseServer(config, cache, repo, logger),
		repo:          repo,
		pluginFactory: pluginFactory,

		pluginManager: manager,
		gatewayCache:  gatewayCache,
		rulesCache:    rulesCache,
		pluginCache:   pluginCache,
	}

	// Subscribe to gateway events
	go s.subscribeToEvents()

	return s
}

func (s *ProxyServer) Run() error {
	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)

	// Add middleware to handle system routes first
	s.router.Use(func(c *gin.Context) {
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

	// Add middleware chain
	s.router.Use(s.middlewareHandler())

	// Add catch-all route for proxying
	s.router.Any("/*path", s.HandleForward)

	// Start the server
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

// Combine middleware handling into a single function for better performance
func (s *ProxyServer) middlewareHandler() gin.HandlerFunc {
	gatewayMiddleware := middleware.NewGatewayMiddleware(s.logger, s.cache, s.config.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.logger, s.repo)

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip middleware for system endpoints
		if strings.HasPrefix(path, "/__/") || path == "/health" {
			s.logger.Debug("Skipping middleware for system endpoint")
			return
		}

		// First identify the gateway
		identifyHandler := gatewayMiddleware.IdentifyGateway()
		identifyHandler(c)

		if c.IsAborted() {
			s.logger.Debug("Gateway identification failed")
			return
		}

		isPublic := isPublicRoute(c, s.cache)

		if !isPublic {
			validateHandler := authMiddleware.ValidateAPIKey()
			validateHandler(c)

			// If auth failed, stop here
			if c.IsAborted() {
				s.logger.Debug("API key validation failed")
				return
			}
		}
		c.Next()
	}
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

	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
		"path":      path,
		"method":    method,
	}).Debug("Processing request")

	// Create the RequestContext
	reqCtx := &types.RequestContext{
		Context:   ctx,
		GatewayID: gatewayID.(string),
		Headers:   make(map[string][]string),
		Method:    method,
		Path:      path,
		Query:     c.Request.URL.Query(),
		Metadata:  make(map[string]interface{}),
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
	if err != nil {
		s.logger.WithError(err).Error("Failed to get gateway data")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"gatewayData": gatewayData,
	}).Debug("Gateway data")

	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range gatewayData.Rules {
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

		// Check path match
		if strings.HasPrefix(path, rule.Path) {
			ruleCopy := rule
			matchingRule = &ruleCopy
			break
		}
	}

	s.logger.WithFields(logrus.Fields{
		"matchingRule": matchingRule,
	}).Debug("Matching rule")

	if matchingRule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found for path and method"})
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

	// Copy response headers and status
	for k, values := range response.Headers {
		for _, v := range values {
			c.Header(k, v)
		}
	}

	c.Data(response.StatusCode, "application/json", response.Body)
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

	var rules []types.ForwardingRule
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

	if err := s.pluginManager.SetPluginChain(types.GatewayLevel, gateway.ID, gatewayChains); err != nil {
		return fmt.Errorf("failed to configure gateway plugins: %w", err)
	}

	// Configure rule-level plugins
	s.logger.WithFields(logrus.Fields{
		"rule": rule,
	}).Debug("Configuring rule plugins")

	if rule != nil && len(rule.PluginChain) > 0 {
		s.logger.WithFields(logrus.Fields{
			"ruleID":  rule.ID,
			"plugins": len(rule.PluginChain),
		}).Debug("Configuring rule plugins")

		if err := s.pluginManager.SetPluginChain(types.RuleLevel, rule.ID, rule.PluginChain); err != nil {
			return fmt.Errorf("failed to configure rule plugins: %w", err)
		}
	}

	return nil
}

func (s *ProxyServer) getGatewayData(ctx context.Context, gatewayID string) (*types.GatewayData, error) {
	logger := ctx.Value("logger").(*logrus.Logger)

	// Try to get from memory cache first
	if cached, ok := s.gatewayCache.Get(gatewayID); ok {
		s.logger.WithFields(logrus.Fields{
			"cached": cached,
		}).Debug("Cached gateway data")
		gatewayData := cached.(*types.GatewayData)
		return gatewayData, nil
	}

	// Try to get from Redis cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	if rulesJSON, err := s.cache.Get(ctx, rulesKey); err == nil {
		// Get gateway from database since we need gateway config
		gateway, err := s.repo.GetGateway(ctx, gatewayID)
		if err != nil {
			return nil, fmt.Errorf("failed to get gateway: %w", err)
		}

		// Parse rules from cache
		var rules []models.ForwardingRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			logger.WithError(err).Warn("Failed to unmarshal rules from cache")
		} else {
			gatewayData := &types.GatewayData{
				Gateway: convertModelToTypesGateway(gateway),
				Rules:   convertModelToTypesRules(ctx, rules),
			}

			// Store in memory cache
			s.gatewayCache.Set(gatewayID, gatewayData)

			logger.WithFields(logrus.Fields{
				"gatewayID":  gatewayID,
				"rulesCount": len(rules),
				"fromCache":  "redis",
			}).Debug("Gateway rules found in Redis cache")

			return gatewayData, nil
		}
	}

	// Get from database as last resort
	gateway, err := s.repo.GetGateway(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway: %w", err)
	}

	rules, err := s.repo.ListRules(ctx, gatewayID)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules: %w", err)
	}

	// Convert models to types
	gatewayData := &types.GatewayData{
		Gateway: convertModelToTypesGateway(gateway),
		Rules:   convertModelToTypesRules(ctx, rules),
	}

	// Store in both caches
	rulesJSON, err := json.Marshal(rules)
	if err == nil {
		s.cache.Set(ctx, rulesKey, string(rulesJSON), 0)
	}
	s.gatewayCache.Set(gatewayID, gatewayData)

	logger.WithFields(logrus.Fields{
		"gatewayID":       gatewayID,
		"enabledPlugins":  gateway.EnabledPlugins,
		"requiredPlugins": gateway.RequiredPlugins,
		"rulesCount":      len(rules),
		"fromCache":       "database",
	}).Debug("Loaded gateway data from database")

	return gatewayData, nil
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
		Status:          g.Status,
		Tier:            g.Tier,
		EnabledPlugins:  g.EnabledPlugins,
		RequiredPlugins: requiredPlugins,
	}
}

func convertModelToTypesRules(ctx context.Context, rules []models.ForwardingRule) []types.ForwardingRule {
	logger := ctx.Value("logger").(*logrus.Logger)
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

		// Create an intermediate structure to handle the wrapped plugins
		var pluginWrapper struct {
			Plugins []types.PluginConfig `json:"plugins"`
		}

		var pluginChain []types.PluginConfig
		logger.WithFields(logrus.Fields{
			"pluginChain": r.PluginChain,
		}).Debug("Plugin chain")

		if r.PluginChain != nil {
			chainJSON, _ := json.Marshal(r.PluginChain)
			if err := json.Unmarshal(chainJSON, &pluginWrapper); err != nil {
				logger.WithError(err).Error("Failed to unmarshal plugin chain")
			} else {
				pluginChain = pluginWrapper.Plugins
			}
		}

		result = append(result, types.ForwardingRule{
			ID:            r.ID,
			GatewayID:     r.GatewayID,
			Path:          r.Path,
			Target:        r.Target,
			Methods:       r.Methods,
			Headers:       headers,
			StripPath:     r.StripPath,
			PreserveHost:  r.PreserveHost,
			RetryAttempts: r.RetryAttempts,
			PluginChain:   pluginChain,
			Active:        r.Active,
			Public:        r.Public,
			CreatedAt:     r.CreatedAt.Format(time.RFC3339),
			UpdatedAt:     r.UpdatedAt.Format(time.RFC3339),
		})
	}
	return result
}

func (s *ProxyServer) forwardRequest(req *types.RequestContext, rule *types.ForwardingRule) (*types.ResponseContext, error) {
	client := &fasthttp.Client{}
	httpReq := fasthttp.AcquireRequest()
	httpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(httpReq)
	defer fasthttp.ReleaseResponse(httpResp)

	// Construct target URL
	targetURL := rule.Target
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL // Default to HTTPS
	}

	// Add path to target URL
	if rule.StripPath {
		// Remove the rule's path prefix from the request path
		targetPath := strings.TrimPrefix(req.Path, rule.Path)
		targetURL = strings.TrimRight(targetURL, "/") + "/" + strings.TrimLeft(targetPath, "/")
		// Remove trailing slash if the target doesn't have one
		targetURL = strings.TrimSuffix(targetURL, "/")
	} else {
		targetURL = strings.TrimRight(targetURL, "/") + req.Path
	}

	// Add query parameters if any
	if len(req.Query) > 0 {
		targetURL += "?" + req.Query.Encode()
	}

	s.logger.WithFields(logrus.Fields{
		"target":     targetURL,
		"method":     req.Method,
		"path":       req.Path,
		"stripPath":  rule.StripPath,
		"rulePath":   rule.Path,
		"ruleTarget": rule.Target,
	}).Debug("Forwarding request")

	// Set request details
	httpReq.SetRequestURI(targetURL)
	httpReq.Header.SetMethod(req.Method)

	// Copy headers
	for k, values := range req.Headers {
		for _, v := range values {
			httpReq.Header.Add(k, v)
		}
	}

	// Set body if present
	if len(req.Body) > 0 {
		httpReq.SetBody(req.Body)
	}

	// Make the request
	if err := client.Do(httpReq, httpResp); err != nil {
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Convert to our Response type
	response := &types.ResponseContext{
		StatusCode: httpResp.StatusCode(),
		Headers:    make(map[string][]string),
		Body:       httpResp.Body(),
	}

	// Copy headers
	httpResp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		v := string(value)
		if response.Headers[k] == nil {
			response.Headers[k] = make([]string, 0)
		}
		response.Headers[k] = append(response.Headers[k], v)
	})

	return response, nil
}

// Add getter for plugin manager
func (s *ProxyServer) PluginManager() *plugins.Manager {
	return s.pluginManager
}

func (s *ProxyServer) convertGatewayPlugins(gateway *types.Gateway) []types.PluginConfig {
	var chains []types.PluginConfig

	s.logger.WithFields(logrus.Fields{
		"gatewayID":      gateway.ID,
		"enabledPlugins": gateway.EnabledPlugins,
	}).Debug("Converting gateway plugins")

	for _, pluginName := range gateway.EnabledPlugins {
		for _, config := range gateway.RequiredPlugins {
			if config.Name == pluginName && config.Enabled {
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
