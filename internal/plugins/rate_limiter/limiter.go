package rate_limiter

import (
	"ai-gateway-ce/internal/types"
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

func (r *RateLimiter) ProcessRequest(ctx *types.RequestContext, respCtx *types.ResponseContext) error {
	// Build rate limit keys
	keys := r.buildRateLimitKeys(ctx)

	// Check global rate limit first
	if r.limitTypes.Global && keys["global"] != "" {
		config, exists := r.limits["global"]
		if exists {
			count, err := r.checkRateLimit(context.Background(), keys["global"], config.Window)
			if err != nil {
				return err
			}

			r.logger.WithFields(logrus.Fields{
				"type":   "global",
				"count":  count,
				"limit":  config.Limit,
				"window": config.Window,
			}).Debug("Checking global rate limit")

			if count > int64(config.Limit) {
				r.addRateLimitHeaders(ctx, config)
				if respCtx.Metadata == nil {
					respCtx.Metadata = make(map[string]interface{})
				}
				respCtx.Metadata["rate_limit_exceeded"] = true
				respCtx.Metadata["rate_limit_type"] = "global"
				respCtx.Metadata["retry_after"] = r.actions.RetryAfter
				return &types.PluginError{
					StatusCode: http.StatusTooManyRequests,
					Message:    "Global rate limit exceeded",
				}
			}
			r.addRateLimitHeaders(ctx, config)
		}
	}

	// Check IP-based rate limit
	if r.limitTypes.PerIP && keys["per_ip"] != "" {
		config, exists := r.limits["per_ip"]
		if exists {
			count, err := r.checkRateLimit(context.Background(), keys["per_ip"], config.Window)
			if err != nil {
				return err
			}

			r.logger.WithFields(logrus.Fields{
				"type":   "per_ip",
				"count":  count,
				"limit":  config.Limit,
				"window": config.Window,
			}).Debug("Checking per-IP rate limit")

			if count > int64(config.Limit) {
				r.addRateLimitHeaders(ctx, config)
				respCtx.Metadata["rate_limit_exceeded"] = true
				respCtx.Metadata["rate_limit_type"] = "IP"
				return &types.PluginError{
					StatusCode: http.StatusTooManyRequests,
					Message:    "IP rate limit exceeded",
				}
			}
			r.addRateLimitHeaders(ctx, config)
		}
	}

	// Check user-based rate limit
	if r.limitTypes.PerUser && keys["per_user"] != "" {
		config, exists := r.limits["per_user"]
		if exists {
			count, err := r.checkRateLimit(context.Background(), keys["per_user"], config.Window)
			if err != nil {
				return err
			}

			r.logger.WithFields(logrus.Fields{
				"type":   "per_user",
				"count":  count,
				"limit":  config.Limit,
				"window": config.Window,
			}).Debug("Checking per-user rate limit")

			if count > int64(config.Limit) {
				r.addRateLimitHeaders(ctx, config)
				respCtx.Metadata["rate_limit_exceeded"] = true
				respCtx.Metadata["rate_limit_type"] = "user"
				return &types.PluginError{
					StatusCode: http.StatusTooManyRequests,
					Message:    "User rate limit exceeded",
				}
			}
			r.addRateLimitHeaders(ctx, config)
		}
	}

	return nil
}

func (r *RateLimiter) ProcessResponse(resp *types.ResponseContext) error {
	return r.processResponse(resp)
}

func (r *RateLimiter) checkRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	now := time.Now().Unix()
	windowStart := now - int64(window.Seconds())

	// Use Redis MULTI to make this atomic
	pipe := r.redis.Pipeline()

	// Clean up old entries
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))

	// Add the current request with a unique score to prevent collisions
	requestID := fmt.Sprintf("%d:%s", now, uuid.New().String())
	pipe.ZAdd(ctx, key, &redis.Z{
		Score:  float64(now),
		Member: requestID,
	})

	// Get the count after adding the current request
	countCmd := pipe.ZCount(ctx, key, strconv.FormatInt(windowStart, 10), strconv.FormatInt(now, 10))

	// Set expiration
	pipe.Expire(ctx, key, window)

	// Execute all commands atomically
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to execute rate limit pipeline: %w", err)
	}

	count, err := countCmd.Result()
	if err != nil {
		return 0, fmt.Errorf("failed to get request count: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"key":          key,
		"currentCount": count,
		"window":       window,
		"windowStart":  windowStart,
		"now":          now,
	}).Debug("Rate limit check")

	return count, nil
}

func (r *RateLimiter) buildRateLimitKeys(ctx *types.RequestContext) map[string]string {
	keys := make(map[string]string)
	base := fmt.Sprintf("ratelimit:%s:%s", ctx.GatewayID, ctx.Path)

	// Global key
	if r.limitTypes.Global {
		keys["global"] = fmt.Sprintf("%s:type:global", base)
	}

	// IP key
	if r.limitTypes.PerIP {
		if ip := ctx.Headers["X-Forwarded-For"]; ip != "" {
			keys["per_ip"] = fmt.Sprintf("%s:type:ip:addr:%s", base, ip)
		}
	}

	// User key
	if r.limitTypes.PerUser {
		if userID := ctx.Headers["X-User-ID"]; userID != "" {
			keys["per_user"] = fmt.Sprintf("%s:type:user:id:%s", base, userID)
		}
	}

	r.logger.WithFields(logrus.Fields{
		"gatewayID": ctx.GatewayID,
		"path":      ctx.Path,
		"keys":      keys,
	}).Debug("Built rate limit keys")

	return keys
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

func (r *RateLimiter) processResponse(resp *types.ResponseContext) error {
	// Update dynamic limits based on response status
	r.updateDynamicLimits(resp)
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
