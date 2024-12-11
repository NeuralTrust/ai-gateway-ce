package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"

	"ai-gateway-ce/internal/cache"
	"ai-gateway-ce/internal/database"
	"ai-gateway-ce/internal/middleware"
	"ai-gateway-ce/internal/plugins"
	"ai-gateway-ce/internal/types"
)

type ProxyServer struct {
	*BaseServer
	repo *database.Repository
}

func NewProxyServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *ProxyServer {
	return &ProxyServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
		repo:       repo,
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

	// Add middleware chain
	s.router.Use(s.middlewareHandler())

	// Add catch-all route for proxying
	s.router.Any("/*path", s.handleForward)

	// Start the server
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

// Combine middleware handling into a single function for better performance
func (s *ProxyServer) middlewareHandler() gin.HandlerFunc {
	gatewayMiddleware := middleware.NewGatewayMiddleware(s.logger, s.cache, s.config.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.logger, s.repo)

	return func(c *gin.Context) {
		path := c.Request.URL.Path

		s.logger.WithFields(logrus.Fields{
			"path":    path,
			"host":    c.Request.Host,
			"method":  c.Request.Method,
			"headers": c.Request.Header,
		}).Debug("Processing request in middleware handler")

		// Skip middleware for system endpoints
		if strings.HasPrefix(path, "/__/") || path == "/health" {
			s.logger.Debug("Skipping middleware for system endpoint")
			return
		}

		// First identify the gateway
		s.logger.Debug("Running gateway identification middleware")
		identifyHandler := gatewayMiddleware.IdentifyGateway()
		identifyHandler(c)

		s.logger.WithField("isAborted", c.IsAborted()).Debug("Gateway middleware completed")
		if c.IsAborted() {
			s.logger.Debug("Gateway identification failed")
			return
		}

		// Check if it's a public route
		isPublic := isPublicRoute(c, s.cache)
		s.logger.WithField("isPublic", isPublic).Debug("Checked if route is public")

		if !isPublic {
			s.logger.Debug("Route is not public, validating API key")
			validateHandler := authMiddleware.ValidateAPIKey()
			validateHandler(c)

			s.logger.WithFields(logrus.Fields{
				"isAborted": c.IsAborted(),
				"status":    c.Writer.Status(),
			}).Debug("Auth middleware completed")

			// If auth failed, stop here
			if c.IsAborted() {
				s.logger.Debug("API key validation failed")
				return
			}
		} else {
			s.logger.Debug("Route is public, skipping API key validation")
		}

		// If we get here, all middleware passed
		s.logger.Debug("All middleware passed, continuing to next handler")

		// Proceed to the next handler
		c.Next()
	}
}

func (s *ProxyServer) handleForward(c *gin.Context) {
	s.logger.WithFields(logrus.Fields{
		"path":   c.Request.URL.Path,
		"method": c.Request.Method,
		"host":   c.Request.Host,
	}).Debug("Starting forward handler")

	// Get gateway ID from context
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

	// Convert *http.Request to *fasthttp.Request
	fasthttpReq, err := convertToFasthttpRequest(c.Request)
	if err != nil {
		s.logger.WithError(err).Error("Failed to convert *http.Request to *fasthttp.Request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Update fasthttpReq URI
	fasthttpReq.SetRequestURI(targetURL)

	// Set headers from rule
	for key, value := range matchingRule.Headers {
		fasthttpReq.Header.Set(key, value)
		s.logger.WithFields(logrus.Fields{
			"header": key,
			"value":  value,
		}).Debug("Adding custom header")
	}

	// Create the RequestContext
	reqCtx := &types.RequestContext{
		Context:   c.Request.Context(),
		GatewayID: gatewayID.(string),
		Headers:   make(map[string]string),
		Method:    string(fasthttpReq.Header.Method()),
		Path:      string(fasthttpReq.URI().Path()),
		Request:   fasthttpReq,
		Body:      fasthttpReq.Body(),
	}

	// Create the ResponseContext
	respCtx := &types.ResponseContext{
		Context:   c.Request.Context(),
		GatewayID: gatewayID.(string),
		Headers:   make(map[string]string),
		Response:  nil,
		Metadata:  make(map[string]interface{}),
	}

	// Execute pre-request plugins
	if len(matchingRule.PluginChain) > 0 {
		// Filter plugins by stage
		var preRequestPlugins []types.PluginConfig
		for _, plugin := range matchingRule.PluginChain {
			if plugin.Stage == "pre_request" {
				preRequestPlugins = append(preRequestPlugins, plugin)
			}
		}

		if len(preRequestPlugins) > 0 {
			pluginManager := plugins.NewManager(s.logger, s.cache.Client())
			if err := pluginManager.ExecutePlugins(preRequestPlugins, reqCtx, respCtx); err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					c.JSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
					return
				}
				s.logger.WithError(err).Error("Plugin execution error")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
				return
			}

			// Check for rate limit exceeded
			if exceeded, ok := respCtx.Metadata["rate_limit_exceeded"].(bool); ok && exceeded {
				limitType := respCtx.Metadata["rate_limit_type"].(string)
				retryAfter := respCtx.Metadata["retry_after"].(string)
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error":       fmt.Sprintf("Rate limit exceeded: %s rate limit exceeded", limitType),
					"retry_after": retryAfter,
				})
				c.Header("Retry-After", retryAfter)
				return
			}
		}
	}

	// Forward the request using fasthttp.Client
	client := &fasthttp.Client{
		// Configure client as needed
	}

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := client.Do(reqCtx.Request, resp); err != nil {
		s.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
	}

	// Update ResponseContext
	respCtx.Response = resp

	// Execute post-request plugins
	if len(matchingRule.PluginChain) > 0 {
		// Filter plugins by stage
		var postRequestPlugins []types.PluginConfig
		for _, plugin := range matchingRule.PluginChain {
			if plugin.Stage == "post_request" {
				postRequestPlugins = append(postRequestPlugins, plugin)
			}
		}

		if len(postRequestPlugins) > 0 {
			pluginManager := plugins.NewManager(s.logger, s.cache.Client())
			if err := pluginManager.ExecutePlugins(postRequestPlugins, reqCtx, respCtx); err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					c.JSON(pluginErr.StatusCode, gin.H{"error": pluginErr.Message})
					return
				}
				s.logger.WithError(err).Error("Plugin execution error")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Plugin execution failed"})
				return
			}
		}
	}

	// Write response back to client
	writeFasthttpResponseToGin(c, resp)
}

// Helper function to convert *http.Request to *fasthttp.Request
func convertToFasthttpRequest(req *http.Request) (*fasthttp.Request, error) {
	fasthttpReq := fasthttp.AcquireRequest()
	// Copy method
	fasthttpReq.Header.SetMethod(req.Method)
	// Copy URL
	fasthttpReq.SetRequestURI(req.URL.String())
	// Copy headers
	for k, vv := range req.Header {
		for _, v := range vv {
			fasthttpReq.Header.Add(k, v)
		}
	}
	// Copy body
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	fasthttpReq.SetBody(bodyBytes)
	// Reset the request body
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return fasthttpReq, nil
}

// Helper function to write fasthttp.Response to gin.Context
func writeFasthttpResponseToGin(c *gin.Context, resp *fasthttp.Response) {
	// Set status code
	c.Status(resp.StatusCode())

	// Copy headers
	resp.Header.VisitAll(func(key, value []byte) {
		c.Header(string(key), string(value))
	})

	// Write body
	c.Writer.Write(resp.Body())
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
