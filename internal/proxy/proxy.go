package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/plugins"
	"ai-gateway/internal/rules"
)

type Proxy struct {
	cache   *cache.Cache
	logger  *logrus.Logger
	client  *http.Client
	plugins *plugins.Registry
}

func NewProxy(cache *cache.Cache, logger *logrus.Logger, pluginRegistry *plugins.Registry) *Proxy {
	return &Proxy{
		cache:   cache,
		logger:  logger,
		client:  &http.Client{},
		plugins: pluginRegistry,
	}
}

func (p *Proxy) Handle(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Tenant not found"})
		return
	}

	// Get rules from cache
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := p.cache.Get(c, key)
	if err != nil {
		p.logger.WithError(err).Error("Failed to get forwarding rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	var forwardingRules []rules.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &forwardingRules); err != nil {
		p.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process request"})
		return
	}

	// Find matching rule
	var matchingRule *rules.ForwardingRule
	requestPath := c.Request.URL.Path
	for _, rule := range forwardingRules {
		if !rule.Active {
			continue
		}

		if strings.HasPrefix(requestPath, rule.Path) {
			// Check if methods are specified and if the current method is allowed
			if len(rule.Methods) > 0 {
				methodAllowed := false
				for _, method := range rule.Methods {
					if method == c.Request.Method {
						methodAllowed = true
						break
					}
				}
				if !methodAllowed {
					continue
				}
			}
			ruleCopy := rule
			matchingRule = &ruleCopy
			break
		}
	}

	if matchingRule == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No matching route found"})
		return
	}

	// Forward the request
	if err := p.forwardRequest(c, matchingRule); err != nil {
		p.logger.WithError(err).Error("Failed to forward request")
		c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
		return
	}
}

func (p *Proxy) forwardRequest(c *gin.Context, rule *rules.ForwardingRule) error {
	targetURL, err := url.Parse(rule.Target)
	if err != nil {
		p.logger.WithError(err).Error("Failed to parse target URL")
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// Get tenant configuration for API key
	tenantID, _ := c.Get(middleware.TenantContextKey)
	key := fmt.Sprintf("tenant:%s", tenantID)
	tenantJSON, err := p.cache.Get(c, key)
	if err != nil {
		p.logger.WithError(err).Error("Failed to get tenant")
		return fmt.Errorf("failed to authenticate request")
	}

	var tenant struct {
		ApiKey string `json:"api_key"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(tenantJSON), &tenant); err != nil {
		p.logger.WithError(err).Error("Failed to unmarshal tenant")
		return fmt.Errorf("failed to authenticate request")
	}

	// Build the target path
	targetPath := c.Request.URL.Path
	if rule.StripPath {
		targetPath = strings.TrimPrefix(targetPath, rule.Path)
	}
	targetURL.Path = path.Join(targetURL.Path, targetPath)

	// Read and store the original body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to read request body")
		return fmt.Errorf("failed to read request body: %w", err)
	}
	// Restore the body for later use
	c.Request.Body = io.NopCloser(bytes.NewReader(body))

	// Create the forwarded request
	forwardReq, err := http.NewRequestWithContext(
		c.Request.Context(),
		c.Request.Method,
		targetURL.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		p.logger.WithError(err).Error("Failed to create forward request")
		return fmt.Errorf("failed to create forward request: %w", err)
	}

	// Copy headers from original request
	for k, v := range c.Request.Header {
		if k != "Host" { // Skip the Host header
			forwardReq.Header[k] = v
		}
	}

	// Add custom headers from rule
	for k, v := range rule.Headers {
		forwardReq.Header.Set(k, v)
	}

	// Add tenant API key to Authorization header if not present
	if forwardReq.Header.Get("Authorization") == "" {
		forwardReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tenant.ApiKey))
	}

	// Set proper Host header
	forwardReq.Host = targetURL.Host

	// Log the forward request details
	p.logger.WithFields(logrus.Fields{
		"method":      forwardReq.Method,
		"target_url":  targetURL.String(),
		"target_host": forwardReq.Host,
		"target_path": targetURL.Path,
		"headers":     forwardReq.Header,
		"body_length": len(body),
	}).Debug("Forwarding request")

	// Forward the request
	var resp *http.Response
	var lastErr error
	attempts := rule.RetryAttempts + 1

	for i := 0; i < attempts; i++ {
		resp, lastErr = p.client.Do(forwardReq)
		if lastErr == nil {
			if resp.StatusCode != http.StatusMisdirectedRequest {
				break
			}
			resp.Body.Close()
			lastErr = fmt.Errorf("misdirected request (421)")
		}

		logFields := logrus.Fields{
			"attempt": i + 1,
			"error":   lastErr.Error(),
		}
		if resp != nil {
			logFields["status_code"] = resp.StatusCode
		}

		p.logger.WithFields(logFields).Warn("Request attempt failed")

		// Create new body reader for retry
		forwardReq.Body = io.NopCloser(bytes.NewReader(body))

		// Wait before retry
		if i < attempts-1 {
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	if lastErr != nil {
		p.logger.WithError(lastErr).Error("All forward attempts failed")
		return fmt.Errorf("failed to forward request after %d attempts: %w", attempts, lastErr)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.WithError(err).Error("Failed to read response body")
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Log response details
	p.logger.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
		"headers":     resp.Header,
		"body_length": len(respBody),
	}).Debug("Received response")

	// If there's an error response, try to parse it
	if resp.StatusCode >= 400 {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(respBody, &errorResp); err == nil {
			p.logger.WithField("error_response", errorResp).Error("Received error response from target")
		}
	}

	// Copy response headers
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}

	// Write response
	c.Writer.WriteHeader(resp.StatusCode)
	_, err = c.Writer.Write(respBody)
	if err != nil {
		p.logger.WithError(err).Error("Failed to write response")
		return fmt.Errorf("failed to write response: %w", err)
	}

	// Execute plugins based on stage
	for _, pluginConfig := range rule.PluginChain {
		if !pluginConfig.Enabled {
			continue
		}

		switch pluginConfig.Stage {
		case rules.StagePreRequest:
			// Pre-request plugin execution
		case rules.StagePostRequest:
			// Post-request plugin execution
		case rules.StagePreResponse:
			// Pre-response plugin execution
		case rules.StagePostResponse:
			// Post-response plugin execution
		}
	}

	return nil
}

func (p *Proxy) executePluginChain(ctx context.Context, stage string, rule *rules.ForwardingRule, req *http.Request, resp *http.Response) error {
	// Create request/response context
	reqCtx := &plugins.RequestContext{
		TenantID:        rule.TenantID,
		OriginalRequest: req,
		ForwardRequest:  req.Clone(ctx),
		Rule:            rule,
		Metadata:        make(map[string]interface{}),
	}

	respCtx := &plugins.ResponseContext{
		TenantID:        rule.TenantID,
		OriginalRequest: req,
		Response:        resp,
		Metadata:        make(map[string]interface{}),
	}

	if rule.PluginChain == nil {
		return nil
	}

	// Filter plugins for this stage
	var stagePlugins []rules.PluginConfig
	for _, pc := range rule.PluginChain {
		if pc.Enabled && pc.Stage == stage {
			stagePlugins = append(stagePlugins, pc)
		}
	}

	// Sort by priority
	sort.Slice(stagePlugins, func(i, j int) bool {
		return stagePlugins[i].Priority < stagePlugins[j].Priority
	})

	// Group plugins by parallel capability
	var serialPlugins, parallelPlugins []rules.PluginConfig
	for _, pc := range stagePlugins {
		if pc.Parallel {
			parallelPlugins = append(parallelPlugins, pc)
		} else {
			serialPlugins = append(serialPlugins, pc)
		}
	}

	// Execute parallel plugins
	if len(parallelPlugins) > 0 {
		errChan := make(chan error, len(parallelPlugins))
		var wg sync.WaitGroup

		for _, pc := range parallelPlugins {
			wg.Add(1)
			go func(config rules.PluginConfig) {
				defer wg.Done()

				plugin, exists := p.plugins.Get(config.Name)
				if !exists {
					errChan <- fmt.Errorf("plugin %s not found", config.Name)
					return
				}

				var err error
				if resp == nil {
					err = plugin.ProcessRequest(ctx, reqCtx)
				} else {
					err = plugin.ProcessResponse(ctx, respCtx)
				}

				if err != nil {
					errChan <- fmt.Errorf("plugin %s failed: %w", config.Name, err)
				}
			}(pc)
		}

		wg.Wait()
		close(errChan)

		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	// Execute serial plugins
	for _, pc := range serialPlugins {
		plugin, exists := p.plugins.Get(pc.Name)
		if !exists {
			return fmt.Errorf("plugin %s not found", pc.Name)
		}

		var err error
		if resp == nil {
			err = plugin.ProcessRequest(ctx, reqCtx)
		} else {
			err = plugin.ProcessResponse(ctx, respCtx)
		}

		if err != nil {
			return fmt.Errorf("plugin %s failed: %w", pc.Name, err)
		}
	}

	return nil
}
