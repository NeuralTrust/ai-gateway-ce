package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
	loadBalancers sync.Map // map[string]*LoadBalancer
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
				ID:            rule.ID,
				GatewayID:     rule.GatewayID,
				Path:          rule.Path,
				ServiceID:     rule.ServiceID,
				Methods:       rule.Methods,
				Headers:       rule.Headers,
				StripPath:     rule.StripPath,
				PreserveHost:  rule.PreserveHost,
				RetryAttempts: rule.RetryAttempts,
				PluginChain:   rule.PluginChain,
				Active:        rule.Active,
				Public:        rule.Public,
				CreatedAt:     time.Now().Format(time.RFC3339),
				UpdatedAt:     time.Now().Format(time.RFC3339),
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

	// Convert and cache rules as types
	typesRules := convertModelToTypesRules(rules)
	rulesJSON, err := json.Marshal(typesRules)
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
		Rules:   typesRules,
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
		Status:          g.Status,
		RequiredPlugins: requiredPlugins,
	}
}

func convertModelToTypesRules(rules []models.ForwardingRule) []types.ForwardingRule {
	var result []types.ForwardingRule
	for _, r := range rules {
		var pluginChain []types.PluginConfig
		jsonBytes, _ := r.PluginChain.Value()
		if err := json.Unmarshal(jsonBytes.([]byte), &pluginChain); err != nil {
			pluginChain = []types.PluginConfig{} // fallback to empty slice on error
		}

		result = append(result, types.ForwardingRule{
			ID:            r.ID,
			GatewayID:     r.GatewayID,
			Path:          r.Path,
			ServiceID:     r.ServiceID,
			Methods:       r.Methods,
			Headers:       map[string]string(r.Headers),
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
	// Get service for the rule
	service, err := s.repo.GetService(req.Context, rule.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("service not found: %w", err)
	}

	var target *types.UpstreamTarget
	var lb *LoadBalancer
	switch service.Type {
	case models.ServiceTypeUpstream:
		// Get upstream for the service
		upstream, err := s.repo.GetUpstream(req.Context, service.UpstreamID)
		if err != nil {
			return nil, fmt.Errorf("upstream not found: %w", err)
		}

		// Get or create load balancer for the upstream
		lb, err = s.getLoadBalancer(upstream)
		if err != nil {
			return nil, fmt.Errorf("failed to get load balancer: %w", err)
		}

		// Get next target from load balancer
		target, err = lb.NextTarget(req.Context)
		if err != nil {
			return nil, fmt.Errorf("no available targets: %w", err)
		}

	case models.ServiceTypeEndpoint:
		// Create target from service's direct configuration
		target = &types.UpstreamTarget{
			Host:        service.Host,
			Port:        service.Port,
			Protocol:    service.Protocol,
			Path:        service.Path,
			Headers:     service.Headers,
			Credentials: types.Credentials(service.Credentials),
		}

	default:
		return nil, fmt.Errorf("unsupported service type: %s", service.Type)
	}

	// Rest of the existing forwardRequest logic remains the same
	client := &fasthttp.Client{}
	httpReq := fasthttp.AcquireRequest()
	httpResp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(httpReq)
	defer fasthttp.ReleaseResponse(httpResp)

	// Build target URL based on target type
	var targetURL string
	if target.Provider != "" {
		// For provider targets, infer host based on provider
		var host string
		switch target.Provider {
		case "openai":
			host = "api.openai.com"
		case "anthropic":
			host = "api.anthropic.com"
		case "cohere":
			host = "api.cohere.ai"
		default:
			return nil, fmt.Errorf("unsupported provider: %s", target.Provider)
		}

		targetURL = fmt.Sprintf("https://%s%s",
			host,
			target.Path, // Use the path configured in the upstream target
		)
	} else {
		// For regular backend targets
		targetURL = fmt.Sprintf("%s://%s:%d%s",
			target.Protocol,
			target.Host,
			target.Port,
			target.Path,
		)
	}

	if rule.StripPath {
		targetURL = strings.TrimSuffix(targetURL, "/") + strings.TrimPrefix(req.Path, rule.Path)
	}

	// Set request details
	httpReq.SetRequestURI(targetURL)
	httpReq.Header.SetMethod(req.Method)
	httpReq.SetBody(req.Body)

	// Copy headers
	for k, v := range req.Headers {
		for _, val := range v {
			httpReq.Header.Add(k, val)
		}
	}

	// Apply authentication
	s.applyAuthentication(httpReq, &target.Credentials, req.Body)

	// Make the request
	err = client.Do(httpReq, httpResp)
	if err != nil {
		if service.Type == models.ServiceTypeUpstream {
			lb.ReportFailure(target, err)
		}
		return nil, fmt.Errorf("failed to forward request: %w", err)
	}

	// Report success if status code is 2xx
	if httpResp.StatusCode() >= 200 && httpResp.StatusCode() < 300 {
		if service.Type == models.ServiceTypeUpstream {
			lb.ReportSuccess(target)
		}
	} else if service.Type == models.ServiceTypeUpstream {
		lb.ReportFailure(target, fmt.Errorf("upstream returned status code %d", httpResp.StatusCode))
	}

	// Create response
	return s.createResponse(httpResp), nil
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

func (s *ProxyServer) getLoadBalancer(upstream *models.Upstream) (*LoadBalancer, error) {
	if lb, ok := s.loadBalancers.Load(upstream.ID); ok {
		return lb.(*LoadBalancer), nil
	}

	lb := NewLoadBalancer(upstream, s.logger, s.cache)
	s.loadBalancers.Store(upstream.ID, lb)
	return lb, nil
}
