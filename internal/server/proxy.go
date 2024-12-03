package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/plugins"
	"ai-gateway/internal/types"
)

var (
	// Pre-compile the ping response
	pingResponseBytes = []byte(`{"message":"pong"}`)

	// Transport pool for better connection reuse
	transport = &http.Transport{
		MaxIdleConns:        2000,
		IdleConnTimeout:     120 * time.Second,
		DisableCompression:  true,
		MaxIdleConnsPerHost: 2000,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
	}

	// Shared HTTP client
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Rules cache with RWMutex for thread-safe access
	rulesCache = struct {
		sync.RWMutex
		rules map[string][]types.ForwardingRule
	}{
		rules: make(map[string][]types.ForwardingRule),
	}
)

type ProxyServer struct {
	*BaseServer
	pluginManager *plugins.Manager
	pipeline      *RequestPipeline
}

func NewProxyServer(config *Config, cache *cache.Cache, logger *logrus.Logger) *ProxyServer {
	pipeline := NewRequestPipeline(50, 100)

	server := &ProxyServer{
		BaseServer:    NewBaseServer(config, cache, logger),
		pluginManager: plugins.NewManager(logger, cache.GetRedisClient()),
		pipeline:      pipeline,
	}

	pipeline.Start()
	return server
}

func (s *ProxyServer) handleForward(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	path := c.Request.URL.Path
	s.logger.WithFields(logrus.Fields{
		"tenant_id": tenantID,
		"path":      path,
		"method":    c.Request.Method,
	}).Debug("Handling forward request")

	// Get rules from cache
	rulesCache.RLock()
	rules, exists := rulesCache.rules[tenantID.(string)]
	rulesCache.RUnlock()

	if !exists {
		// Fallback to Redis if not in cache
		rulesKey := fmt.Sprintf("rules:%s", tenantID)
		rulesJSON, err := s.cache.Get(c, rulesKey)
		if err != nil {
			if err.Error() == "redis: nil" {
				c.JSON(http.StatusNotFound, gin.H{"error": "No rules found"})
				return
			}
			s.logger.WithError(err).Error("Failed to get forwarding rules")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}

		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal rules")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
			return
		}
	}

	// Find matching rule
	var matchingRule *types.ForwardingRule
	for _, rule := range rules {
		if rule.Active && strings.HasPrefix(path, rule.Path) {
			ruleCopy := rule
			matchingRule = &ruleCopy
			break
		}
	}

	if matchingRule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found"})
		return
	}

	// Create request context
	reqCtx := &types.RequestContext{
		Ctx:             c.Request.Context(),
		TenantID:        tenantID.(string),
		OriginalRequest: c.Request,
		ForwardRequest:  c.Request.Clone(c.Request.Context()),
		Rule:            matchingRule,
		Metadata:        make(map[string]interface{}),
	}

	// Execute plugins
	if err := s.pluginManager.ExecutePlugins(matchingRule.PluginChain, reqCtx); err != nil {
		// Handle plugin error properly
		if pluginErr, ok := err.(*types.PluginError); ok {
			// Set any headers from the forward request
			for k, v := range reqCtx.ForwardRequest.Header {
				for _, headerValue := range v {
					c.Writer.Header().Add(k, headerValue)
				}
			}
			// If we have a validation response, use it
			if reqCtx.ValidationResponse != nil {
				c.Data(pluginErr.StatusCode, "application/json", reqCtx.ValidationResponse)
				return
			}
			// Otherwise use the plugin error
			c.JSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
			return
		}
		s.logger.WithError(err).Error("Plugin execution error")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
		return
	}

	// Check if we should stop forwarding and return validation response
	if reqCtx.StopForwarding {
		if reqCtx.ValidationResponse != nil {
			s.logger.Debug("Returning validation response")
			c.Data(http.StatusOK, "application/json", reqCtx.ValidationResponse)
			return
		}
		// If StopForwarding is true but no validation response, return generic error
		c.JSON(http.StatusForbidden, gin.H{"error": "Request blocked by plugin"})
		return
	}

	// Forward the request if no validation response
	if err := s.forwardRequest(c, matchingRule); err != nil {
		s.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request"})
		return
	}
}

func (s *ProxyServer) forwardRequest(c *gin.Context, rule *types.ForwardingRule) error {
	// Pre-allocate request/response from pool
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Build target URI
	targetURL := rule.Target
	if rule.StripPath {
		// If we're stripping the path, just use the target as is
		req.SetRequestURI(targetURL)
	} else {
		// If not stripping, append the full path to target
		req.SetRequestURI(targetURL + c.Request.URL.Path)
	}

	// Set method and headers
	req.Header.SetMethod(c.Request.Method)
	req.Header.SetContentType(c.Request.Header.Get("Content-Type"))

	// Read and set body
	if c.Request.Body != nil {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		req.SetBody(body)
	}

	// Only copy essential headers
	if auth := c.Request.Header.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if host := c.Request.Header.Get("Host"); host != "" && rule.PreserveHost {
		req.Header.Set("Host", host)
	}

	// Forward request with timeout
	if err := fastClient.DoTimeout(req, resp, 5*time.Second); err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}

	// Write response directly
	c.Writer.WriteHeader(resp.StatusCode())
	resp.BodyWriteTo(c.Writer)

	return nil
}

func (s *ProxyServer) handlePluginError(c *gin.Context, err error) {
	s.logger.WithError(err).Debug("Handling plugin error")

	if pluginErr, ok := err.(*types.PluginError); ok {
		s.logger.WithFields(logrus.Fields{
			"status_code": pluginErr.StatusCode,
			"message":     pluginErr.Message,
		}).Info("Plugin error response")

		c.AbortWithStatusJSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
		return
	}

	s.logger.Error("Unknown plugin error")
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
}

func (s *ProxyServer) Run() error {
	// Setup routes
	s.setupRoutes()

	// Initial rules cache population
	s.refreshRulesCache()

	// Start periodic refresh
	s.startRulesCacheRefresh()

	// Start the server
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

func (s *ProxyServer) setupRoutes() {
	// Use gin release mode for better performance
	gin.SetMode(gin.ReleaseMode)

	// Disable gin's debug logging
	gin.DisableConsoleColor()
	gin.DefaultWriter = ioutil.Discard

	// 1. System endpoints (no auth required, no middleware)
	systemGroup := s.router.Group("/__")
	{
		systemGroup.GET("/ping", func(c *gin.Context) {
			c.Data(http.StatusOK, "application/json", pingResponseBytes)
		})
		systemGroup.GET("/health", s.handleHealthCheck)
	}

	// 2. All other routes with middleware
	apiGroup := s.router.Group("/")
	{
		// Apply middleware only to non-system routes
		apiGroup.Use(s.middlewareHandler())

		// Admin routes
		apiGroup.Any("/api/:path", s.handleForward)

		// Proxy endpoints
		apiGroup.Any("/:path", s.handleForward)
	}
}

// Combine middleware handling into a single function for better performance
func (s *ProxyServer) middlewareHandler() gin.HandlerFunc {
	tenantMiddleware := middleware.NewTenantMiddleware(s.logger, s.cache, s.config.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.cache, s.logger)

	return func(c *gin.Context) {
		// Fast path for ping
		if c.Request.URL.Path == "/__ping" {
			c.Next()
			return
		}

		// Use a sync.Pool for request contexts
		reqCtx := requestContextPool.Get().(*types.RequestContext)
		defer requestContextPool.Put(reqCtx)

		if isPublicRoute(c, s.cache) {
			tenantMiddleware.IdentifyTenant()(c)
		} else {
			tenantMiddleware.IdentifyTenant()(c)
			authMiddleware.ValidateAPIKey()(c)
		}
		c.Next()
	}
}

// Add a sync.Pool for request contexts
var requestContextPool = sync.Pool{
	New: func() interface{} {
		return &types.RequestContext{
			Metadata: make(map[string]interface{}),
		}
	},
}

// Helper function to check if a route is public
func isPublicRoute(c *gin.Context, cache *cache.Cache) bool {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		return false
	}

	// Get rules for tenant
	rulesKey := fmt.Sprintf("rules:%s", tenantID)
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

func (s *ProxyServer) handlePing(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.Write(pingResponseBytes)
}

// Add this function to ProxyServer
func (s *ProxyServer) handleHealthCheck(c *gin.Context) {
	// Simple health check response
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

var requestBatcher = &sync.Pool{
	New: func() interface{} {
		return make(chan *http.Request, 100)
	},
}

func (s *ProxyServer) batchRequests() {
	batch := requestBatcher.Get().(chan *http.Request)
	defer requestBatcher.Put(batch)

	// Process requests in batches
	for len(batch) > 0 {
		reqs := make([]*http.Request, 0, len(batch))
		for req := range batch {
			reqs = append(reqs, req)
			if len(reqs) >= 10 {
				break
			}
		}
		s.processBatch(reqs)
	}
}

func (s *ProxyServer) processBatch(reqs []*http.Request) {
	for _, req := range reqs {
		resp, err := httpClient.Do(req)
		if err != nil {
			s.logger.WithError(err).Error("Failed to process batch request")
			continue
		}
		resp.Body.Close()
	}
}

// Add this method to ProxyServer
func (s *ProxyServer) startRulesCacheRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			s.refreshRulesCache()
		}
	}()
}

func (s *ProxyServer) refreshRulesCache() {
	// Get all tenants
	tenantsKey := "tenants"
	tenantsJSON, err := s.cache.Get(context.Background(), tenantsKey)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get tenants for rules refresh")
		return
	}

	var tenants []types.Tenant
	if err := json.Unmarshal([]byte(tenantsJSON), &tenants); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal tenants")
		return
	}

	// Temporary map for new rules
	newRules := make(map[string][]types.ForwardingRule)

	// Get rules for each tenant
	for _, tenant := range tenants {
		rulesKey := fmt.Sprintf("rules:%s", tenant.ID)
		rulesJSON, err := s.cache.Get(context.Background(), rulesKey)
		if err != nil {
			continue // Skip if no rules found
		}

		var rules []types.ForwardingRule
		if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
			continue // Skip if unmarshal fails
		}

		newRules[tenant.ID] = rules
	}

	// Update the trie as well
	newTrie := make(map[string]*routeTrie)
	for tenantID, rules := range newRules {
		root := &routeTrie{
			children: make(map[string]*routeTrie),
		}

		for _, rule := range rules {
			parts := strings.Split(strings.Trim(rule.Path, "/"), "/")
			current := root

			for _, part := range parts {
				if next, ok := current.children[part]; ok {
					current = next
				} else {
					next = &routeTrie{
						children: make(map[string]*routeTrie),
					}
					current.children[part] = next
					current = next
				}
			}
			current.rule = &rule
		}
		newTrie[tenantID] = root
	}

	// Update both caches atomically
	rulesCache.Lock()
	rulesTrie.Lock()
	rulesCache.rules = newRules
	rulesTrie.trie = newTrie
	rulesTrie.Unlock()
	rulesCache.Unlock()

	s.logger.Debug("Rules cache and trie refreshed")
}

type routeTrie struct {
	children map[string]*routeTrie
	rule     *types.ForwardingRule
}

var rulesTrie = struct {
	sync.RWMutex
	trie map[string]*routeTrie
}{
	trie: make(map[string]*routeTrie),
}

func (s *ProxyServer) findRule(tenantID, path string) *types.ForwardingRule {
	rulesTrie.RLock()
	defer rulesTrie.RUnlock()

	if tenant, ok := rulesTrie.trie[tenantID]; ok {
		return tenant.findMatch(path)
	}
	return nil
}

// Add this method to routeTrie
func (t *routeTrie) findMatch(path string) *types.ForwardingRule {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	current := t

	for _, part := range parts {
		if next, ok := current.children[part]; ok {
			current = next
		} else if next, ok := current.children["*"]; ok {
			current = next
		} else {
			break
		}
	}

	return current.rule
}

// ... rest of the implementation ...

var clientPool = &sync.Pool{
	New: func() interface{} {
		return &http.Client{
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				DisableKeepAlives:   false,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
			Timeout: 10 * time.Second,
		}
	},
}
