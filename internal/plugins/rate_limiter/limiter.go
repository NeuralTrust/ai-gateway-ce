package rate_limiter

import (
	"ai-gateway-ce/internal/types"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

type RateLimitTypes struct {
	Global  bool
	PerUser bool
	PerIP   bool
}

type RateLimitConfig struct {
	Limit  int
	Window time.Duration
}

type RateLimitAction struct {
	Type            string // "block", "degrade", "notify"
	RetryAfter      string
	FallbackService string
}

type RateLimiter struct {
	redis      *redis.Client
	logger     *logrus.Logger
	limitTypes *RateLimitTypes
	limits     map[string]RateLimitConfig
	actions    *RateLimitAction
	mu         sync.RWMutex
	name       string
}

func NewRateLimiter(redis *redis.Client, logger *logrus.Logger) *RateLimiter {
	return &RateLimiter{
		redis:  redis,
		logger: logger,
		name:   "rate_limiter",
		limitTypes: &RateLimitTypes{
			Global:  true,
			PerUser: true,
			PerIP:   true,
		},
		limits: make(map[string]RateLimitConfig),
		actions: &RateLimitAction{
			Type:       "block",
			RetryAfter: "60",
		},
	}
}

func (r *RateLimiter) Name() string {
	return "rate_limiter"
}

func (r *RateLimiter) GetName() string {
	return r.Name()
}

func (r *RateLimiter) ProcessRequest(ctx *types.RequestContext, pluginCtx *types.PluginContext) error {
	return r.processRequest(ctx, pluginCtx)
}

func (r *RateLimiter) ProcessResponse(ctx *types.ResponseContext, pluginCtx *types.PluginContext) error {
	return r.processResponse(ctx, pluginCtx)
}

func (r *RateLimiter) checkRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	pipe := r.redis.Pipeline()
	now := time.Now().Unix()
	windowStart := now - int64(window.Seconds())

	// Clean up old entries
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

	// Add current request
	requestID := fmt.Sprintf("%d:%s", now, uuid.New().String())
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(now),
		Member: requestID,
	})

	// Set expiration
	pipe.Expire(ctx, key, window)

	// Get current count
	count := pipe.ZCard(ctx, key)

	// Execute pipeline
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to check rate limit: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"key":    key,
		"count":  count.Val(),
		"window": window,
	}).Debug("Rate limit check")

	return count.Val(), nil
}

func (r *RateLimiter) buildRateLimitKeys(reqCtx *types.RequestContext) map[string]string {
	keys := make(map[string]string)
	base := fmt.Sprintf("ratelimit:%s:%s", reqCtx.GatewayID, reqCtx.Path)

	// Per-User limit (most specific)
	if r.limitTypes.PerUser {
		if userID := reqCtx.Headers["X-User-ID"]; userID != "" {
			keys["per_user"] = fmt.Sprintf("%s:type:user:id:%s", base, userID)
		}
	}

	// Per-IP limit
	if r.limitTypes.PerIP {
		if ip := r.getClientIP(reqCtx.Request); ip != "" {
			keys["per_ip"] = fmt.Sprintf("%s:type:ip:addr:%s", base, ip)
		}
	}

	// Global limit (least specific)
	if r.limitTypes.Global {
		keys["global"] = fmt.Sprintf("%s:type:global", base)
	}

	r.logger.WithFields(logrus.Fields{
		"gatewayID": reqCtx.GatewayID,
		"path":      reqCtx.Path,
		"keys":      keys,
	}).Debug("Built rate limit keys")

	return keys
}

func (r *RateLimiter) cleanupKeys(ctx context.Context, reqCtx *types.RequestContext) {
	keys := r.buildRateLimitKeys(reqCtx)
	for _, key := range keys {
		if err := r.redis.Del(ctx, key).Err(); err != nil {
			r.logger.WithError(err).WithField("key", key).Warn("Failed to cleanup rate limit key")
		}
	}
}

func (r *RateLimiter) handleRateLimitExceeded(reqCtx *types.RequestContext, err error) error {
	// Set content type to JSON
	reqCtx.Headers["Content-Type"] = "application/json"

	// Add retry-after header if configured
	if r.actions != nil && r.actions.RetryAfter != "" {
		reqCtx.Headers["Retry-After"] = r.actions.RetryAfter
	}

	switch r.actions.Type {
	case "block":
		return &types.PluginError{
			StatusCode: http.StatusTooManyRequests,
			Message:    fmt.Sprintf("Rate limit exceeded: %s", err.Error()),
		}
	case "degrade":
		if r.actions.FallbackService != "" {
			reqCtx.Headers["X-Original-Host"] = string(reqCtx.Request.URI().Host())
			reqCtx.Request.SetHost(r.actions.FallbackService)
			return nil
		}
	case "notify":
		r.notifyRateLimitExceeded(reqCtx, err)
		return nil
	}

	return &types.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Message:    fmt.Sprintf("Rate limit exceeded: %s", err.Error()),
	}
}

func (r *RateLimiter) addRateLimitHeaders(reqCtx *types.RequestContext, limitConfig RateLimitConfig) {
	reqCtx.Headers["X-RateLimit-Limit"] = strconv.Itoa(limitConfig.Limit)
	reqCtx.Headers["X-RateLimit-Window"] = limitConfig.Window.String()
	if r.actions != nil && r.actions.RetryAfter != "" {
		reqCtx.Headers["Retry-After"] = r.actions.RetryAfter
	}
}

func (r *RateLimiter) updateDynamicLimits(respCtx *types.ResponseContext) {
	statusCode := respCtx.Response.StatusCode()
	if statusCode >= 500 {
		r.mu.Lock()
		defer r.mu.Unlock()

		// Implement dynamic rate limiting logic here
		// For example, reduce limits temporarily when backend is struggling
	}
}

func (r *RateLimiter) getClientIP(req *fasthttp.Request) string {
	// Try X-Forwarded-For header
	if xff := string(req.Header.Peek("X-Forwarded-For")); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP header
	if xrip := string(req.Header.Peek("X-Real-IP")); xrip != "" {
		return xrip
	}

	// Fall back to remote address
	return string(req.Header.Peek("X-Real-IP"))
}

func (r *RateLimiter) notifyRateLimitExceeded(reqCtx *types.RequestContext, err error) {
	notification := map[string]interface{}{
		"tenant_id": reqCtx.GatewayID,
		"path":      reqCtx.Path,
		"error":     err.Error(),
		"timestamp": time.Now(),
	}

	// Implement notification logic here (e.g., send to monitoring system)
	r.logger.WithFields(logrus.Fields(notification)).Warn("Rate limit exceeded")
}

func (r *RateLimiter) Configure(config types.PluginConfig) error {
	r.logger.WithFields(logrus.Fields{
		"config": config,
	}).Debug("Configuring rate limiter")

	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize default values if Settings is nil
	if config.Settings == nil {
		config.Settings = make(map[string]interface{})
	}

	// Reset all state
	r.limits = make(map[string]RateLimitConfig)
	r.limitTypes = &RateLimitTypes{
		Global:  false,
		PerUser: false,
		PerIP:   false,
	}

	// Configure limit types
	if types, ok := config.Settings["limit_types"].(map[string]interface{}); ok {
		r.limitTypes.Global = types["global"] == true
		r.limitTypes.PerUser = types["per_user"] == true
		r.limitTypes.PerIP = types["per_ip"] == true
	}

	// Configure limits
	if limits, ok := config.Settings["limits"].(map[string]interface{}); ok {
		for limitType, config := range limits {
			if configMap, ok := config.(map[string]interface{}); ok {
				limit, _ := configMap["limit"].(float64)
				if limit <= 0 {
					limit = 100 // default limit
				}

				window := "1m" // default window
				if w, ok := configMap["window"].(string); ok && w != "" {
					window = w
				}

				windowDuration, err := time.ParseDuration(window)
				if err != nil {
					r.logger.WithFields(logrus.Fields{
						"limitType": limitType,
						"window":    window,
						"error":     err,
					}).Error("Invalid window duration, using default")
					windowDuration = time.Minute // default to 1 minute
				}

				// Only add the limit if its type is enabled
				switch limitType {
				case "global":
					if r.limitTypes.Global {
						r.limits["global"] = RateLimitConfig{
							Limit:  int(limit),
							Window: windowDuration,
						}
					}
				case "per_ip":
					if r.limitTypes.PerIP {
						r.limits["per_ip"] = RateLimitConfig{
							Limit:  int(limit),
							Window: windowDuration,
						}
					}
				case "per_user":
					if r.limitTypes.PerUser {
						r.limits["per_user"] = RateLimitConfig{
							Limit:  int(limit),
							Window: windowDuration,
						}
					}
				}

				r.logger.WithFields(logrus.Fields{
					"limitType": limitType,
					"limit":     limit,
					"window":    window,
					"enabled":   r.limits[limitType].Limit > 0,
				}).Debug("Configured rate limit")
			}
		}
	}

	// Configure actions with safe defaults
	actionType := "block" // default action type
	retryAfter := "60"    // default retry after in seconds
	fallbackService := "" // default empty fallback service

	if actions, ok := config.Settings["actions"].(map[string]interface{}); ok {
		if t, ok := actions["type"].(string); ok && t != "" {
			actionType = t
		}
		if ra, ok := actions["retry_after"].(string); ok && ra != "" {
			retryAfter = ra
		}
		if fs, ok := actions["fallback_service"].(string); ok {
			fallbackService = fs
		}
	}

	r.actions = &RateLimitAction{
		Type:            actionType,
		RetryAfter:      retryAfter,
		FallbackService: fallbackService,
	}

	r.logger.WithFields(logrus.Fields{
		"type":            r.actions.Type,
		"retryAfter":      r.actions.RetryAfter,
		"fallbackService": r.actions.FallbackService,
		"limitTypes":      r.limitTypes,
		"limits":          r.limits,
	}).Debug("Configured rate limiter")

	return nil
}

func (r *RateLimiter) processRequest(ctx *types.RequestContext, pluginCtx *types.PluginContext) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	r.logger.WithFields(logrus.Fields{
		"gatewayID": ctx.GatewayID,
		"path":      ctx.Path,
		"method":    ctx.Method,
		"headers":   ctx.Headers,
	}).Debug("Processing request")

	// Build rate limit keys
	keys := r.buildRateLimitKeys(ctx)

	// Check per-user limit first (most specific)
	if userKey, ok := keys["per_user"]; ok {
		if config, exists := r.limits["per_user"]; exists {
			count, err := r.checkRateLimit(ctx.Context, userKey, config.Window)
			if err != nil {
				return err
			}
			if count > int64(config.Limit) {
				return r.handleRateLimitExceeded(ctx, fmt.Errorf("user rate limit exceeded"))
			}
			// Add rate limit headers
			r.addRateLimitHeaders(ctx, config)
		}
	}

	// Then check per-IP limit
	if ipKey, ok := keys["per_ip"]; ok {
		if config, exists := r.limits["per_ip"]; exists {
			count, err := r.checkRateLimit(ctx.Context, ipKey, config.Window)
			if err != nil {
				return err
			}
			if count > int64(config.Limit) {
				return r.handleRateLimitExceeded(ctx, fmt.Errorf("IP rate limit exceeded"))
			}
			// Add rate limit headers
			r.addRateLimitHeaders(ctx, config)
		}
	}

	// Finally check global limit (least specific)
	if globalKey, ok := keys["global"]; ok {
		if config, exists := r.limits["global"]; exists {
			count, err := r.checkRateLimit(ctx.Context, globalKey, config.Window)
			if err != nil {
				return err
			}
			if count > int64(config.Limit) {
				return r.handleRateLimitExceeded(ctx, fmt.Errorf("global rate limit exceeded"))
			}
			// Add rate limit headers
			r.addRateLimitHeaders(ctx, config)
		}
	}

	return nil
}

func (r *RateLimiter) processResponse(ctx *types.ResponseContext, pluginCtx *types.PluginContext) error {
	// Update dynamic limits based on response status
	r.updateDynamicLimits(ctx)
	return nil
}

func (r *RateLimiter) Parallel() bool {
	// Rate limiter should run sequentially to maintain accurate rate limiting
	return false
}

func (r *RateLimiter) Priority() int {
	// Rate limiter should run early in the chain
	return 1
}

func (r *RateLimiter) Stage() types.ExecutionStage {
	// Rate limiter should run in the pre-request stage
	return types.PreRequest
}
