package server

import (
	"ai-gateway-ce/internal/plugins"
	"ai-gateway-ce/internal/types"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

// Pre-encoded responses
var (
	pingResponse     = []byte(`{"message":"pong"}`)
	healthResponse   = []byte(`{"status":"ok"}`)
	notFoundResponse = []byte(`{"error":"not found"}`)
)

func (s *ProxyServer) handleFastPing(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	ctx.Write(pingResponse)
}

func (s *ProxyServer) handleFastHealth(ctx *fasthttp.RequestCtx) {
	ctx.SetContentType("application/json")
	ctx.Write(healthResponse)
}

func (s *ProxyServer) handleFastForward(ctx *fasthttp.RequestCtx) {
	// Get gateway ID from subdomain
	host := string(ctx.Host())
	subdomain := strings.Split(host, ".")[0]

	s.logger.WithFields(logrus.Fields{
		"host":      host,
		"subdomain": subdomain,
		"path":      string(ctx.Path()),
		"method":    string(ctx.Method()),
	}).Debug("Processing request")

	// Get gateway ID from cache
	subdomainKey := fmt.Sprintf("subdomain:%s", subdomain)
	gatewayID, err := s.cache.Get(ctx, subdomainKey)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"subdomain": subdomain,
			"error":     err,
		}).Error("Failed to get gateway ID")
		ctx.Error("Gateway not found", fasthttp.StatusNotFound)
		return
	}

	s.logger.WithFields(logrus.Fields{
		"subdomain": subdomain,
		"gatewayID": gatewayID,
	}).Debug("Found gateway ID")

	// Get rules from cache
	rulesKey := fmt.Sprintf("rules:%s", gatewayID)
	rulesJSON, err := s.cache.Get(ctx, rulesKey)
	if err != nil {
		s.logger.WithFields(logrus.Fields{
			"gatewayID": gatewayID,
			"error":     err,
		}).Error("Failed to get rules")
		ctx.Error("Failed to get rules", fasthttp.StatusInternalServerError)
		return
	}

	s.logger.WithFields(logrus.Fields{
		"gatewayID": gatewayID,
		"rules":     rulesJSON,
	}).Debug("Found rules")

	var rules []types.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &rules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		ctx.Error("Failed to process rules", fasthttp.StatusInternalServerError)
		return
	}

	// Find matching rule
	path := string(ctx.Path())
	method := string(ctx.Method())
	var matchingRule *types.ForwardingRule

	for _, rule := range rules {
		if !rule.Active {
			continue
		}

		if strings.HasPrefix(path, rule.Path) {
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
			ruleCopy := rule
			matchingRule = &ruleCopy
			break
		}
	}

	if matchingRule == nil {
		ctx.Error("No matching rule found", fasthttp.StatusNotFound)
		return
	}

	// Create forwarded request from pool
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Copy original request
	ctx.Request.CopyTo(req)

	// Set target URL
	targetURL := matchingRule.Target
	if !matchingRule.StripPath {
		targetURL += path
	} else {
		targetURL += strings.TrimPrefix(path, matchingRule.Path)
	}
	req.SetRequestURI(targetURL)

	// Execute plugins if needed
	if len(matchingRule.PluginChain) > 0 {
		pluginManager := plugins.NewManager(s.logger, s.cache.Client())

		// Convert headers to map
		headers := make(map[string]string)
		ctx.Request.Header.VisitAll(func(key, value []byte) {
			headers[string(key)] = string(value)
		})

		// Create request context
		reqCtx := &types.RequestContext{
			Context:   ctx,
			GatewayID: gatewayID,
			Path:      path,
			Method:    method,
			Headers:   headers,
			Body:      ctx.Request.Body(),
			Request:   &ctx.Request,
			Response:  &ctx.Response,
			Metadata:  make(map[string]interface{}),
		}

		s.logger.WithFields(logrus.Fields{
			"gatewayID": gatewayID,
			"path":      path,
			"method":    method,
			"headers":   headers,
		}).Debug("Created request context")

		// Execute plugins
		if err := pluginManager.ExecutePlugins(matchingRule.PluginChain, reqCtx, nil); err != nil {
			s.logger.WithError(err).Error("Plugin execution failed")
			if pluginErr, ok := err.(*types.PluginError); ok {
				ctx.SetContentType("application/json")
				ctx.SetStatusCode(pluginErr.StatusCode)
				ctx.SetBodyString(fmt.Sprintf(`{"error":"%s"}`, pluginErr.Message))
			} else {
				ctx.SetContentType("application/json")
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				ctx.SetBodyString(`{"error":"Plugin execution failed"}`)
			}
			return
		}

		// Apply any modifications from plugins
		if reqCtx.Modified {
			reqCtx.Request.CopyTo(req)
		}
	}

	// Submit request to pipeline
	resp := s.pipeline.Submit(req)
	defer fasthttp.ReleaseResponse(resp)

	// Copy response to context
	resp.CopyTo(&ctx.Response)
}
