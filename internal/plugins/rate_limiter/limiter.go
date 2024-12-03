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
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/types"
)

type RateLimiter struct {
	redis       *redis.Client
	logger      *logrus.Logger
	tiers       map[string]RateLimitTier
	defaultTier string
	limitTypes  RateLimitType
	dynamic     *DynamicConfig
	mu          sync.RWMutex
	quota       *QuotaConfig
	actions     *RateLimitAction
}

type RateLimitTier struct {
	Name     string        `json:"name"`
	Limit    int           `json:"limit"`
	Window   time.Duration `json:"window"`
	Burst    int           `json:"burst"`
	Priority int           `json:"priority"`
}

type RateLimitType struct {
	Global    bool               `json:"global"`
	PerIP     bool               `json:"per_ip"`
	PerUser   bool               `json:"per_user"`
	PerMethod bool               `json:"per_method"`
	CostBased bool               `json:"cost_based"`
	Costs     map[string]float64 `json:"endpoint_costs"`
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
	Tiers       map[string]RateLimitTier `json:"tiers"`
	DefaultTier string                   `json:"default_tier"`
	LimitTypes  RateLimitType            `json:"limit_types"`
	Dynamic     *DynamicConfig           `json:"dynamic,omitempty"`
	Quota       *QuotaConfig             `json:"quota,omitempty"`
	Actions     *RateLimitAction         `json:"actions,omitempty"`
	RedisClient *redis.Client
}

func NewRateLimiter(redis *redis.Client, logger *logrus.Logger, config types.PluginConfig) (*RateLimiter, error) {
	if redis == nil {
		return nil, fmt.Errorf("redis client is required")
	}

	logger.WithField("config", config).Debug("Creating rate limiter with config")

	// Initialize with default values
	rl := &RateLimiter{
		redis:       redis,
		logger:      logger,
		tiers:       make(map[string]RateLimitTier),
		defaultTier: "basic",
		limitTypes: RateLimitType{
			Global: true,
		},
	}

	// Parse settings if available
	if settings := config.Settings; settings != nil {
		// Parse tiers
		if tiersConfig, ok := settings["tiers"].(map[string]interface{}); ok {
			for name, t := range tiersConfig {
				if tierMap, ok := t.(map[string]interface{}); ok {
					window := "1m"
					if w, ok := tierMap["window"].(string); ok {
						window = w
					}
					windowDuration, err := time.ParseDuration(window)
					if err != nil {
						windowDuration = time.Minute
					}

					limit := 5
					if l, ok := tierMap["limit"].(float64); ok {
						limit = int(l)
					}

					burst := 0
					if b, ok := tierMap["burst"].(float64); ok {
						burst = int(b)
					}

					rl.tiers[name] = RateLimitTier{
						Name:     name,
						Limit:    limit,
						Window:   windowDuration,
						Burst:    burst,
						Priority: 1,
					}
				}
			}
		}

		// Set default tier
		if defaultTier, ok := settings["default_tier"].(string); ok {
			rl.defaultTier = defaultTier
		}
	}

	// Log the initialized configuration
	rl.logger.WithFields(logrus.Fields{
		"tiers":        rl.tiers,
		"default_tier": rl.defaultTier,
		"limit_types":  rl.limitTypes,
	}).Debug("Rate limiter initialized")

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
	// Get tier from header or metadata
	tier := r.getTierForRequest(reqCtx)

	// Create Redis key for this tenant's rate limit
	key := fmt.Sprintf("ratelimit:%s", reqCtx.TenantID)

	// Use sliding window with Redis
	now := time.Now().Unix()
	windowStart := now - int64(tier.Window.Seconds())

	// First, clean up old entries
	err := r.redis.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10)).Err()
	if err != nil {
		return fmt.Errorf("failed to clean up old entries: %w", err)
	}

	// Get current count
	count, err := r.redis.ZCard(ctx, key).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to get rate limit count: %w", err)
	}

	// Check if we would exceed the limit
	if count >= int64(tier.Limit) {
		ttl := r.redis.TTL(ctx, key).Val()
		if ttl < 0 {
			ttl = tier.Window
		}

		r.logger.WithFields(logrus.Fields{
			"tenant_id": reqCtx.TenantID,
			"limit":     tier.Limit,
			"count":     count,
			"window":    tier.Window.String(),
			"ttl":       ttl.Seconds(),
		}).Warn("Rate limit exceeded")

		// Set response headers
		if reqCtx.ForwardRequest != nil && reqCtx.ForwardRequest.Header != nil {
			reqCtx.ForwardRequest.Header.Set("X-RateLimit-Limit", strconv.Itoa(tier.Limit))
			reqCtx.ForwardRequest.Header.Set("X-RateLimit-Reset", strconv.FormatInt(now+int64(ttl.Seconds()), 10))
			reqCtx.ForwardRequest.Header.Set("Retry-After", strconv.FormatInt(int64(ttl.Seconds()), 10))
		}

		// Return error to stop the request flow
		reqCtx.StopForwarding = true
		return &types.PluginError{
			Message:    fmt.Sprintf("Rate limit exceeded. Try again in %d seconds", int(ttl.Seconds())),
			StatusCode: http.StatusTooManyRequests,
		}
	}

	// Add current request
	err = r.redis.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: now}).Err()
	if err != nil {
		return fmt.Errorf("failed to add request to rate limit: %w", err)
	}

	// Set expiration
	err = r.redis.Expire(ctx, key, tier.Window).Err()
	if err != nil {
		return fmt.Errorf("failed to set expiration: %w", err)
	}

	// Add rate limit headers
	remaining := tier.Limit - int(count) - 1
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Limit", strconv.Itoa(tier.Limit))
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Reset", strconv.FormatInt(now+int64(tier.Window.Seconds()), 10))

	r.logger.WithFields(logrus.Fields{
		"tenant_id": reqCtx.TenantID,
		"limit":     tier.Limit,
		"count":     count + 1,
		"remaining": remaining,
		"window":    tier.Window.String(),
	}).Debug("Rate limit request processed")

	return nil
}

func (r *RateLimiter) ProcessResponse(ctx context.Context, respCtx *types.ResponseContext) error {
	// Update dynamic limits based on response
	if r.dynamic != nil && r.dynamic.AutoScale {
		r.updateDynamicLimits(respCtx)
	}
	return nil
}

func (r *RateLimiter) getTierForRequest(reqCtx *types.RequestContext) RateLimitTier {
	// Log the available tiers for debugging
	r.logger.WithFields(logrus.Fields{
		"tiers":        r.tiers,
		"default_tier": r.defaultTier,
	}).Debug("Getting tier for request")

	// First check for tier in header
	if tierName := reqCtx.OriginalRequest.Header.Get("X-Rate-Limit-Tier"); tierName != "" {
		if tier, ok := r.tiers[tierName]; ok {
			r.logger.WithField("tier", tierName).Debug("Using tier from header")
			return tier
		}
	}

	// Then check metadata
	if tier, exists := reqCtx.Metadata["tier"].(string); exists {
		if t, ok := r.tiers[tier]; ok {
			return t
		}
	}

	// If no tiers are configured, create a default one
	if len(r.tiers) == 0 {
		defaultTier := RateLimitTier{
			Name:     "default",
			Limit:    5,
			Window:   time.Minute,
			Burst:    0,
			Priority: 1,
		}
		r.tiers = map[string]RateLimitTier{
			"default": defaultTier,
		}
		r.defaultTier = "default"
		return defaultTier
	}

	// Use default tier
	if tier, ok := r.tiers[r.defaultTier]; ok {
		return tier
	}

	// If default tier not found, use the first available tier
	for _, tier := range r.tiers {
		return tier
	}

	// Fallback to a basic tier if nothing else is available
	return RateLimitTier{
		Name:     "basic",
		Limit:    5,
		Window:   time.Minute,
		Burst:    0,
		Priority: 1,
	}
}

func (r *RateLimiter) buildRateLimitKeys(reqCtx *types.RequestContext, tier RateLimitTier) []string {
	var keys []string
	base := fmt.Sprintf("ratelimit:%s", reqCtx.TenantID)

	if r.limitTypes.Global {
		keys = append(keys, fmt.Sprintf("%s:global", base))
	}

	if r.limitTypes.PerIP {
		ip := r.getClientIP(reqCtx.OriginalRequest)
		keys = append(keys, fmt.Sprintf("%s:ip:%s", base, ip))
	}

	if r.limitTypes.PerUser {
		if userID := reqCtx.OriginalRequest.Header.Get("X-User-ID"); userID != "" {
			keys = append(keys, fmt.Sprintf("%s:user:%s", base, userID))
		}
	}

	if r.limitTypes.PerMethod {
		keys = append(keys, fmt.Sprintf("%s:method:%s", base, reqCtx.OriginalRequest.Method))
	}

	return keys
}

func (r *RateLimiter) checkLimit(ctx context.Context, key string, tier RateLimitTier) error {
	// Use sliding window with Redis
	now := time.Now().Unix()
	windowStart := now - int64(tier.Window.Seconds())

	pipe := r.redis.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart, 10))
	pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: now})
	pipe.ZCard(ctx, key)
	pipe.Expire(ctx, key, tier.Window)

	cmders, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis pipeline failed: %w", err)
	}

	count := cmders[2].(*redis.IntCmd).Val()
	limit := int64(tier.Limit)
	if count > limit {
		return fmt.Errorf("rate limit exceeded: %d/%d", count, limit)
	}

	return nil
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

	quotaKey := fmt.Sprintf("quota:%s:%s", reqCtx.TenantID, time.Now().Format("2006-01-02"))

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

func (r *RateLimiter) addRateLimitHeaders(reqCtx *types.RequestContext, tier RateLimitTier) {
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Limit", strconv.Itoa(tier.Limit))
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Window", tier.Window.String())
	if r.actions != nil && r.actions.RetryAfter != "" {
		reqCtx.ForwardRequest.Header.Set("Retry-After", r.actions.RetryAfter)
	}
}

func (r *RateLimiter) updateDynamicLimits(respCtx *types.ResponseContext) {
	if respCtx.Response.StatusCode >= 500 {
		r.mu.Lock()
		defer r.mu.Unlock()

		// Reduce limits temporarily
		for _, tier := range r.tiers {
			tier.Limit = int(float64(tier.Limit) * r.dynamic.LoadFactor)
		}
	}
}

func (r *RateLimiter) sendNotification(ctx context.Context, reqCtx *types.RequestContext, err error) {
	notification := map[string]interface{}{
		"tenant_id": reqCtx.TenantID,
		"path":      reqCtx.OriginalRequest.URL.Path,
		"error":     err.Error(),
		"timestamp": time.Now(),
	}

	payload, _ := json.Marshal(notification)
	http.Post(r.actions.NotificationWebhook, "application/json", bytes.NewReader(payload))
}
