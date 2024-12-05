package rate_limiter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/types"
)

type RateLimitConfig struct {
	Limit  int           `json:"limit"`
	Window time.Duration `json:"window"`
}

type RateLimiter struct {
	redis      *redis.Client
	logger     *logrus.Logger
	limits     map[string]RateLimitConfig
	limitTypes RateLimitType
	dynamic    *DynamicConfig
	quota      *QuotaConfig
	actions    *RateLimitAction
	mu         sync.RWMutex
}

type RateLimitType struct {
	Global  bool `json:"global"`
	PerIP   bool `json:"per_ip"`
	PerUser bool `json:"per_user"`
}

type DynamicConfig struct {
	AutoScale      bool    `json:"auto_scale"`
	ConcurrencyMax int     `json:"concurrency_max"`
	ErrorThreshold float64 `json:"error_threshold"`
	LoadFactor     float64 `json:"load_factor"`
}

type QuotaConfig struct {
	Daily     int    `json:"daily"`
	Monthly   int    `json:"monthly"`
	Rollover  bool   `json:"rollover"`
	ResetTime string `json:"reset_time"`
}

type RateLimitAction struct {
	OnExceeded          string `json:"on_exceeded"`
	RetryAfter          string `json:"retry_after"`
	FallbackService     string `json:"fallback_service"`
	AlertThreshold      int    `json:"alert_threshold"`
	NotificationWebhook string `json:"notification_webhook"`
}

type Config struct {
	LimitTypes  RateLimitType    `json:"limit_types"`
	Dynamic     *DynamicConfig   `json:"dynamic,omitempty"`
	Quota       *QuotaConfig     `json:"quota,omitempty"`
	Actions     *RateLimitAction `json:"actions,omitempty"`
	RedisClient *redis.Client
}

func NewRateLimiter(redis *redis.Client, logger *logrus.Logger, config types.PluginConfig) (*RateLimiter, error) {
	if redis == nil {
		return nil, fmt.Errorf("redis client is required")
	}

	logger.WithField("config", config).Debug("Creating rate limiter with config")

	// Initialize with default values
	rl := &RateLimiter{
		redis:  redis,
		logger: logger,
		limits: make(map[string]RateLimitConfig),
		limitTypes: RateLimitType{
			Global: true,
		},
	}

	// Parse settings if available
	if settings := config.Settings; settings != nil {
		// Parse limit types first
		if limitTypes, ok := settings["limit_types"].(map[string]interface{}); ok {
			rl.limitTypes.Global, _ = limitTypes["global"].(bool)
			rl.limitTypes.PerIP, _ = limitTypes["per_ip"].(bool)
			rl.limitTypes.PerUser, _ = limitTypes["per_user"].(bool)
		}

		// Parse limits
		if limitsConfig, ok := settings["limits"].(map[string]interface{}); ok {
			for limitType, config := range limitsConfig {
				if configMap, ok := config.(map[string]interface{}); ok {
					window := "1m"
					if w, ok := configMap["window"].(string); ok {
						window = w
					}
					windowDuration, err := time.ParseDuration(window)
					if err != nil {
						windowDuration = time.Minute
					}

					limit := 5
					if l, ok := configMap["limit"].(float64); ok {
						limit = int(l)
					}

					rl.limits[limitType] = RateLimitConfig{
						Limit:  limit,
						Window: windowDuration,
					}

					logger.WithFields(logrus.Fields{
						"type":   limitType,
						"limit":  limit,
						"window": windowDuration,
					}).Debug("Added rate limit config")
				}
			}
		}
	}

	return rl, nil
}

func (r *RateLimiter) Name() string {
	return "rate_limiter"
}

func (r *RateLimiter) Priority() int {
	return 1
}

func (r *RateLimiter) Stage() types.ExecutionStage {
	return types.PreRequest
}

func (r *RateLimiter) Parallel() bool {
	return false
}

func (r *RateLimiter) ProcessRequest(ctx context.Context, reqCtx *types.RequestContext) error {
	// Build all applicable rate limit keys based on limit types
	keys := r.buildRateLimitKeys(reqCtx)
	r.logger.WithFields(logrus.Fields{
		"gatewayID": reqCtx.GatewayID,
		"keys":      keys,
		"limits":    r.limits,
	}).Debug("Processing rate limits")

	// First check all limits without incrementing
	for _, limitType := range []string{"global", "per_user", "per_ip"} {
		limitConfig, exists := r.limits[limitType]
		if !exists {
			continue
		}

		key, exists := keys[limitType]
		if !exists {
			continue
		}

		// Check if we would exceed the limit
		allowed, count, ttl, err := r.checkLimitWithoutIncrement(ctx, key, limitConfig)
		if err != nil {
			return fmt.Errorf("failed to check rate limit: %w", err)
		}

		if !allowed {
			r.logger.WithFields(logrus.Fields{
				"type":  limitType,
				"count": count,
				"limit": limitConfig.Limit,
				"key":   key,
				"ttl":   ttl.Seconds(),
			}).Warn("Rate limit exceeded")

			return &types.PluginError{
				StatusCode: http.StatusTooManyRequests,
				Message:    fmt.Sprintf("Rate limit exceeded for %s. Try again in %d seconds", limitType, int(ttl.Seconds())),
			}
		}
	}

	// If all limits pass, increment all counters
	for _, limitType := range []string{"global", "per_user", "per_ip"} {
		limitConfig, exists := r.limits[limitType]
		if !exists {
			continue
		}

		key, exists := keys[limitType]
		if !exists {
			continue
		}

		if err := r.incrementLimit(ctx, key, limitConfig); err != nil {
			return fmt.Errorf("failed to increment rate limit: %w", err)
		}
	}

	return nil
}

func (r *RateLimiter) checkLimitWithoutIncrement(ctx context.Context, key string, limitConfig RateLimitConfig) (bool, int64, time.Duration, error) {
	now := time.Now().Unix()
	windowSize := int64(limitConfig.Window.Seconds())
	windowStart := now - windowSize

	// Clean up old entries and check count
	script := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local windowStart = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])

		-- Clean up old entries
		redis.call('ZREMRANGEBYSCORE', key, 0, windowStart)

		-- Get current count
		local count = redis.call('ZCARD', key)

		-- Check if limit would be exceeded
		if count >= limit then
			return {count, 0}  -- not allowed
		end

		return {count, 1}  -- allowed
	`

	// Execute the script
	result, err := r.redis.Eval(ctx, script, []string{key},
		now,               // ARGV[1] - current timestamp
		windowStart,       // ARGV[2] - window start
		limitConfig.Limit, // ARGV[3] - limit
	).Result()

	if err != nil {
		return false, 0, 0, fmt.Errorf("failed to execute rate limit script: %w", err)
	}

	// Parse result
	resultArray, ok := result.([]interface{})
	if !ok || len(resultArray) != 2 {
		return false, 0, 0, fmt.Errorf("invalid result format from rate limit script")
	}

	count := resultArray[0].(int64)
	allowed := resultArray[1].(int64) == 1

	// Get TTL
	ttl := r.redis.TTL(ctx, key).Val()
	if ttl < 0 {
		ttl = time.Duration(windowSize) * time.Second
	}

	r.logger.WithFields(logrus.Fields{
		"key":     key,
		"count":   count,
		"limit":   limitConfig.Limit,
		"allowed": allowed,
		"ttl":     ttl,
	}).Debug("Checked rate limit")

	return allowed, count, ttl, nil
}

func (r *RateLimiter) incrementLimit(ctx context.Context, key string, limitConfig RateLimitConfig) error {
	now := time.Now().Unix()
	windowSize := int64(limitConfig.Window.Seconds())

	// Add request to the limit
	script := `
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local windowSize = tonumber(ARGV[2])

		-- Add current request with unique ID
		local member = string.format("%d:%s", now, ARGV[3])
		redis.call('ZADD', key, now, member)
		redis.call('EXPIRE', key, windowSize)

		return redis.call('ZCARD', key)
	`

	// Generate unique request ID
	requestID := uuid.New().String()

	// Execute the script
	result, err := r.redis.Eval(ctx, script, []string{key},
		now,        // ARGV[1] - current timestamp
		windowSize, // ARGV[2] - window size
		requestID,  // ARGV[3] - unique request ID
	).Result()

	if err != nil {
		return fmt.Errorf("failed to increment rate limit: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"key":       key,
		"count":     result,
		"window":    windowSize,
		"requestID": requestID,
	}).Debug("Incremented rate limit")

	return nil
}

func (r *RateLimiter) ProcessResponse(ctx context.Context, respCtx *types.ResponseContext) error {
	// Update dynamic limits based on response
	if r.dynamic != nil && r.dynamic.AutoScale {
		r.updateDynamicLimits(respCtx)
	}
	return nil
}

func (r *RateLimiter) buildRateLimitKeys(reqCtx *types.RequestContext) map[string]string {
	keys := make(map[string]string)
	base := fmt.Sprintf("ratelimit:%s:%s", reqCtx.GatewayID, reqCtx.OriginalRequest.URL.Path)

	// Build keys in order of most restrictive to least restrictive
	// Per-User limit (most restrictive)
	if r.limitTypes.PerUser {
		if userID := reqCtx.OriginalRequest.Header.Get("X-User-ID"); userID != "" {
			keys["per_user"] = fmt.Sprintf("%s:user:%s", base, userID)
		}
	}

	// Per-IP limit
	if r.limitTypes.PerIP {
		ip := r.getClientIP(reqCtx.OriginalRequest)
		if ip != "" {
			keys["per_ip"] = fmt.Sprintf("%s:ip:%s", base, ip)
		}
	}

	// Global limit (least restrictive)
	if r.limitTypes.Global {
		keys["global"] = fmt.Sprintf("%s:global", base)
	}

	r.logger.WithFields(logrus.Fields{
		"gatewayID": reqCtx.GatewayID,
		"path":      reqCtx.OriginalRequest.URL.Path,
		"keys":      keys,
	}).Debug("Built rate limit keys")

	return keys
}

func (r *RateLimiter) getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(req.RemoteAddr)
	return ip
}

func (r *RateLimiter) checkQuota(ctx context.Context, reqCtx *types.RequestContext) error {
	if r.quota == nil {
		return nil
	}

	quotaKey := fmt.Sprintf("quota:%s:%s", reqCtx.GatewayID, time.Now().Format("2006-01-02"))

	// Check daily quota
	dailyCount, err := r.redis.Incr(ctx, quotaKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check quota: %w", err)
	}

	if dailyCount == 1 {
		r.redis.Expire(ctx, quotaKey, 24*time.Hour)
	}

	if dailyCount > int64(r.quota.Daily) {
		return fmt.Errorf("daily quota exceeded: %d/%d", dailyCount, r.quota.Daily)
	}

	return nil
}

func (r *RateLimiter) handleLimitExceeded(ctx context.Context, reqCtx *types.RequestContext, err error) error {
	if r.actions == nil {
		return err
	}

	switch r.actions.OnExceeded {
	case "delay":
		time.Sleep(time.Second) // Simple delay
		return nil
	case "degrade":
		if r.actions.FallbackService != "" {
			reqCtx.ForwardRequest.URL.Host = r.actions.FallbackService
			return nil
		}
	case "notify":
		if r.actions.NotificationWebhook != "" {
			go r.sendNotification(ctx, reqCtx, err)
		}
	}

	return err
}

func (r *RateLimiter) addRateLimitHeaders(reqCtx *types.RequestContext, limitConfig RateLimitConfig) {
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Limit", strconv.Itoa(limitConfig.Limit))
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Window", limitConfig.Window.String())
	if r.actions != nil && r.actions.RetryAfter != "" {
		reqCtx.ForwardRequest.Header.Set("Retry-After", r.actions.RetryAfter)
	}
}

func (r *RateLimiter) updateDynamicLimits(respCtx *types.ResponseContext) {
	if respCtx.Response.StatusCode >= 500 {
		r.mu.Lock()
		defer r.mu.Unlock()

		// Reduce limits temporarily
		for _, limitConfig := range r.limits {
			limitConfig.Limit = int(float64(limitConfig.Limit) * r.dynamic.LoadFactor)
		}
	}
}

func (r *RateLimiter) sendNotification(ctx context.Context, reqCtx *types.RequestContext, err error) {
	notification := map[string]interface{}{
		"tenant_id": reqCtx.GatewayID,
		"path":      reqCtx.OriginalRequest.URL.Path,
		"error":     err.Error(),
		"timestamp": time.Now(),
	}

	payload, _ := json.Marshal(notification)
	http.Post(r.actions.NotificationWebhook, "application/json", bytes.NewReader(payload))
}

func (r *RateLimiter) getLimitTypeFromKey(key string) string {
	parts := strings.Split(key, ":")
	if len(parts) < 3 {
		return "global"
	}
	return parts[2] // Returns "global", "ip", "user", "method", etc.
}
