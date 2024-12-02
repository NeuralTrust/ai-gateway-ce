package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// Sensitive headers that should be masked in logs
var sensitiveHeaders = map[string]bool{
	"Authorization":  true,
	"X-Api-Key":      true,
	"Api-Key":        true,
	"Password":       true,
	"Token":          true,
	"Secret":         true,
	"X-Access-Token": true,
	"Access-Token":   true,
}

type RequestTimings struct {
	PreRequestStart  time.Time
	PreRequestEnd    time.Time
	RequestStart     time.Time
	RequestEnd       time.Time
	PostRequestStart time.Time
	PostRequestEnd   time.Time
	Total            time.Duration
}

type ProxyServer struct {
	*BaseServer
}

func NewProxyServer(config *Config, cache *cache.Cache, logger *logrus.Logger) *ProxyServer {
	return &ProxyServer{
		BaseServer: NewBaseServer(config, cache, logger),
	}
}

func (s *ProxyServer) setupRoutes() {
	s.setupHealthCheck()

	// All other routes go through tenant identification and forwarding
	tenantMiddleware := middleware.NewTenantMiddleware(s.logger, s.cache, s.config.BaseDomain)
	authMiddleware := middleware.NewAuthMiddleware(s.cache, s.logger)

	s.router.Use(tenantMiddleware.IdentifyTenant())
	s.router.Use(authMiddleware.ValidateAPIKey())
	s.router.NoRoute(s.handleForward)
}

func (s *ProxyServer) Run() error {
	s.setupRoutes()
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

func (s *ProxyServer) handleForward(c *gin.Context) {
	startTime := time.Now()
	timings := &RequestTimings{
		PreRequestStart: startTime,
	}

	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	path := c.Request.URL.Path
	s.logger.WithFields(logrus.Fields{
		"method": c.Request.Method,
		"path":   path,
	}).Debug("Starting request processing")

	// Pre-request processing
	rule, err := s.findMatchingRule(c, tenantID.(string))
	if err != nil {
		s.logger.WithError(err).Error("Failed to find matching rule")
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching rule found"})
		return
	}

	timings.PreRequestEnd = time.Now()
	timings.RequestStart = time.Now()

	// Forward the request
	if err := s.forwardRequest(c, rule, timings); err != nil {
		s.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to forward request"})
		return
	}

	// Calculate total time
	timings.Total = time.Since(startTime)

	// Log timings
	s.logger.WithFields(logrus.Fields{
		"method":          c.Request.Method,
		"path":            path,
		"pre_request_ms":  timings.PreRequestEnd.Sub(timings.PreRequestStart).Milliseconds(),
		"request_ms":      timings.RequestEnd.Sub(timings.RequestStart).Milliseconds(),
		"post_request_ms": timings.PostRequestEnd.Sub(timings.PostRequestStart).Milliseconds(),
		"total_ms":        timings.Total.Milliseconds(),
	}).Debug("Request timing breakdown")
}

func (s *ProxyServer) findMatchingRule(c *gin.Context, tenantID string) (*types.ForwardingRule, error) {
	rulesKey := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := s.cache.Get(c, rulesKey)
	if err != nil {
		return nil, err
	}

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		return nil, err
	}

	path := c.Request.URL.Path
	for _, rule := range rules {
		if rule.Active && strings.HasPrefix(path, rule.Path) {
			return &rule, nil
		}
	}

	return nil, fmt.Errorf("no matching rule found")
}

func (s *ProxyServer) forwardRequest(c *gin.Context, rule *types.ForwardingRule, timings *RequestTimings) error {
	targetURL, err := url.Parse(rule.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// Build request
	targetPath := c.Request.URL.Path
	if rule.StripPath {
		targetPath = strings.TrimPrefix(targetPath, rule.Path)
	}
	targetURL.Path = path.Join(targetURL.Path, targetPath)

	// Read body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	// Create forward request
	forwardReq, err := http.NewRequestWithContext(
		c.Request.Context(),
		c.Request.Method,
		targetURL.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("failed to create forward request: %w", err)
	}

	// Copy headers
	safeHeaders := make(map[string][]string)
	for k, v := range c.Request.Header {
		if k != "Host" {
			forwardReq.Header[k] = v
			if !sensitiveHeaders[k] {
				safeHeaders[k] = v
			}
		}
	}

	// Add rule headers
	for k, v := range rule.Headers {
		forwardReq.Header.Set(k, v)
		if !sensitiveHeaders[k] {
			safeHeaders[k] = []string{v}
		}
	}

	// Set host
	if rule.PreserveHost {
		forwardReq.Host = c.Request.Host
	} else {
		forwardReq.Host = targetURL.Host
	}

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(forwardReq)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	timings.RequestEnd = time.Now()
	timings.PostRequestStart = time.Now()

	// Copy response
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}
	c.Writer.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(c.Writer, resp.Body); err != nil {
		return fmt.Errorf("failed to copy response: %w", err)
	}

	timings.PostRequestEnd = time.Now()

	return nil
}

// Helper functions to mask sensitive data
func maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func maskPath(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if isIDOrToken(part) {
			parts[i] = maskString(part)
		}
	}
	return strings.Join(parts, "/")
}

func isIDOrToken(s string) bool {
	// Check if string looks like an ID or token
	if len(s) >= 20 || // Long strings are likely tokens
		strings.Contains(s, "key-") ||
		strings.Contains(s, "token-") ||
		strings.Contains(s, "secret-") {
		return true
	}
	return false
}
