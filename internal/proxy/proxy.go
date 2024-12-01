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
		return err
	}

	// Build the target path
	targetPath := c.Request.URL.Path
	if rule.StripPath {
		targetPath = strings.TrimPrefix(targetPath, rule.Path)
	}
	targetURL.Path = path.Join(targetURL.Path, targetPath)

	// Create the forwarded request
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}

	forwardReq, err := http.NewRequestWithContext(
		c.Request.Context(),
		c.Request.Method,
		targetURL.String(),
		bytes.NewReader(body),
	)
	if err != nil {
		return err
	}

	// Copy headers
	for k, v := range c.Request.Header {
		forwardReq.Header[k] = v
	}

	// Add custom headers from rule
	for k, v := range rule.Headers {
		forwardReq.Header.Set(k, v)
	}

	// Handle host header
	if rule.PreserveHost {
		forwardReq.Host = c.Request.Host
	}

	// Execute pre-request plugins
	if err := p.executePluginChain(c.Request.Context(), "pre_request", rule, forwardReq, nil); err != nil {
		return fmt.Errorf("pre-request plugins failed: %w", err)
	}

	// Execute the request
	resp, err := p.client.Do(forwardReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Execute post-request plugins
	if err := p.executePluginChain(c.Request.Context(), "post_request", rule, forwardReq, nil); err != nil {
		return fmt.Errorf("post-request plugins failed: %w", err)
	}

	// Execute pre-response plugins
	if err := p.executePluginChain(c.Request.Context(), "pre_response", rule, nil, resp); err != nil {
		return fmt.Errorf("pre-response plugins failed: %w", err)
	}

	// Copy response to client
	// Copy response headers
	for k, v := range resp.Header {
		c.Writer.Header()[k] = v
	}

	// Copy response status
	c.Writer.WriteHeader(resp.StatusCode)

	// Copy response body
	_, err = io.Copy(c.Writer, resp.Body)

	// Execute post-response plugins
	if err := p.executePluginChain(c.Request.Context(), "post_response", rule, nil, resp); err != nil {
		return fmt.Errorf("post-response plugins failed: %w", err)
	}

	return err
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
