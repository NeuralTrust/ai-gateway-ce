package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/database"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/plugins"
	"ai-gateway/internal/types"
)

type ProxyServer struct {
	*BaseServer
}

func NewProxyServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *ProxyServer {
	return &ProxyServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
	}
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

	// Add gateway middleware for non-system routes
	s.router.Use(s.middlewareHandler())

	// Add catch-all route for proxying
	s.router.Any("/*path", s.handleForward)

	// Start the server
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

// Combine middleware handling into a single function for better performance
func (s *ProxyServer) middlewareHandler() gin.HandlerFunc {
	gatewayMiddleware := middleware.NewGatewayMiddleware(s.logger, s.cache, s.config.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.cache, s.logger)

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		// Skip middleware for system endpoints
		if strings.HasPrefix(path, "/__/") {
			c.Next()
			return
		}

		// Skip middleware for root health check
		if path == "/health" {
			c.Next()
			return
		}

		// Always identify gateway first
		gatewayMiddleware.IdentifyGateway()(c)

		// If gateway identification failed, the middleware will have aborted the chain
		if c.IsAborted() {
			return
		}

		// Now we can check if it's a public route
		if !isPublicRoute(c, s.cache) {
			authMiddleware.ValidateAPIKey()(c)
		}

		c.Next()
	}
}

func (s *ProxyServer) handleForward(c *gin.Context) {
	gatewayID, exists := c.Get(middleware.GatewayContextKey)
	if !exists {
		s.logger.Error("Gateway ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
		"path":      c.Request.URL.Path,
		"method":    c.Request.Method,
		"headers":   c.Request.Header,
	}).Debug("Handling forward request")

	// Get rules for gateway
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"error":     err.Error(),
			"gatewayID": gatewayID,
			"rulesKey":  rulesKey,
		}).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get rules"})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
		"rulesJSON": rulesJSON,
	}).Debug("Retrieved rules from cache")

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithFields(logrus.Fields{
			"error":     err.Error(),
			"gatewayID": gatewayID,
			"rulesJSON": rulesJSON,
		}).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to unmarshal rules"})
		return
	}

	// Find matching rule
	path := c.Request.URL.Path
	method := c.Request.Method
	var matchingRule *types.ForwardingRule
	for _, rule := range rules {
		s.logger.WithFields(logrus.Fields{
			"rulePath":      rule.Path,
			"requestPath":   path,
			"ruleMethods":   rule.Methods,
			"requestMethod": method,
			"active":        rule.Active,
			"hasPrefix":     strings.HasPrefix(path, rule.Path),
			"pluginChain":   rule.PluginChain,
		}).Debug("Checking rule match")

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
			// Create a copy of the rule to avoid modifying the slice element
			ruleCopy := rule
			matchingRule = &ruleCopy
			break
		}
	}

	if matchingRule == nil {
		s.logger.WithFields(logrus.Fields{
			"path":      path,
			"method":    method,
			"gatewayID": gatewayID,
			"rules":     rules,
		}).Error("No matching rule found")
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found for path and method"})
		return
	}

	s.logger.WithFields(logrus.Fields{
		"rulePath":    matchingRule.Path,
		"ruleTarget":  matchingRule.Target,
		"stripPath":   matchingRule.StripPath,
		"requestPath": path,
		"pluginChain": matchingRule.PluginChain,
	}).Debug("Found matching rule")

	// Forward the request
	targetURL := matchingRule.Target
	if !matchingRule.StripPath {
		targetURL += path
	} else if strings.HasPrefix(path, matchingRule.Path) {
		// If stripping path, remove the rule path prefix
		targetURL += strings.TrimPrefix(path, matchingRule.Path)
	}

	s.logger.WithFields(logrus.Fields{
		"targetURL":  targetURL,
		"stripPath":  matchingRule.StripPath,
		"origPath":   path,
		"ruleTarget": matchingRule.Target,
	}).Debug("Preparing forward request")

	// Create the forwarded request
	req, err := http.NewRequestWithContext(c.Request.Context(), method, targetURL, c.Request.Body)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"error":     err.Error(),
			"targetURL": targetURL,
			"method":    method,
		}).Error("Failed to create forward request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create forward request"})
		return
	}

	// Copy headers
	for k, v := range c.Request.Header {
		if k != "Host" { // Skip the Host header
			req.Header[k] = v
			s.logger.WithFields(logrus.Fields{
				"header": k,
				"value":  v,
			}).Debug("Copying header")
		}
	}

	// Add custom headers from rule
	for _, header := range matchingRule.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			req.Header.Set(key, value)
			s.logger.WithFields(logrus.Fields{
				"header": key,
				"value":  value,
			}).Debug("Adding custom header")
		}
	}

	// Set proper Host header if needed
	if matchingRule.PreserveHost {
		req.Host = c.Request.Host
		s.logger.WithField("host", req.Host).Debug("Preserving host header")
	}

	// Create request context for plugins
	reqCtx := &types.RequestContext{
		Ctx:             c.Request.Context(),
		GatewayID:       gatewayID.(string),
		OriginalRequest: c.Request,
		ForwardRequest:  req,
		StopForwarding:  false,
		Metadata:        make(map[string]interface{}),
	}

	// Execute pre-request plugins
	if len(matchingRule.PluginChain) > 0 {
		pluginManager := plugins.NewManager(s.logger, s.cache.Client())
		if err := pluginManager.ExecutePlugins(matchingRule.PluginChain, reqCtx); err != nil {
			if pluginErr, ok := err.(*types.PluginError); ok {
				c.JSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
				return
			}
			s.logger.WithError(err).Error("Plugin execution error")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
			return
		}
	}

	// Forward the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	s.logger.WithFields(logrus.Fields{
		"method":  req.Method,
		"url":     req.URL.String(),
		"headers": req.Header,
		"host":    req.Host,
	}).Debug("Sending forward request")

	resp, err := client.Do(req)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"url":   req.URL.String(),
		}).Error("Failed to forward request")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	s.logger.WithFields(logrus.Fields{
		"statusCode": resp.StatusCode,
		"headers":    resp.Header,
	}).Debug("Received response")

	// Create response context for plugins
	respCtx := &types.ResponseContext{
		Ctx:             c.Request.Context(),
		GatewayID:       gatewayID.(string),
		OriginalRequest: c.Request,
		Response:        resp,
		Metadata:        make(map[string]interface{}),
	}

	// Execute post-request plugins
	if len(matchingRule.PluginChain) > 0 {
		pluginManager := plugins.NewManager(s.logger, s.cache.Client())
		if err := pluginManager.ExecutePlugins(matchingRule.PluginChain, respCtx); err != nil {
			if pluginErr, ok := err.(*types.PluginError); ok {
				c.JSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
				return
			}
			s.logger.WithError(err).Error("Plugin execution error")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
			return
		}
	}

	// Copy response headers
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}

	// Set status code and copy body
	c.Writer.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		s.logger.WithError(err).Error("Failed to copy response body")
	}
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
