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

	"ai-gateway/internal/plugins"
)

type RateLimiter struct {
	redis       *redis.Client
	logger      *logrus.Logger
	tiers       map[string]RateLimitTier
	defaultTier string
	limitTypes  RateLimitType
	dynamic     *DynamicConfig
	quota       *QuotaConfig
	actions     *RateLimitAction
	mu          sync.RWMutex
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

func NewRateLimiter(config Config, logger *logrus.Logger) (*RateLimiter, error) {
	if config.RedisClient == nil {
		return nil, fmt.Errorf("redis client is required")
	}

	// Validate tiers
	if len(config.Tiers) == 0 {
		return nil, fmt.Errorf("at least one tier must be defined")
	}

	// Validate default tier
	if _, exists := config.Tiers[config.DefaultTier]; !exists {
		return nil, fmt.Errorf("default tier %s not found in tiers", config.DefaultTier)
	}

	return &RateLimiter{
		redis:       config.RedisClient,
		logger:      logger,
		tiers:       config.Tiers,
		defaultTier: config.DefaultTier,
		limitTypes:  config.LimitTypes,
		dynamic:     config.Dynamic,
		quota:       config.Quota,
		actions:     config.Actions,
	}, nil
}

func (r *RateLimiter) Name() string {
	return "rate_limiter"
}

func (r *RateLimiter) Priority() int {
	return 1
}

func (r *RateLimiter) Stage() plugins.ExecutionStage {
	return plugins.PreRequest
}

func (r *RateLimiter) Parallel() bool {
	return false // Rate limiting must be sequential
}

func (r *RateLimiter) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) error {
	// Get tier from request metadata or use default
	tier := r.getTierForRequest(reqCtx)

	// Build rate limit keys based on configured types
	keys := r.buildRateLimitKeys(reqCtx, tier)

	// Check all applicable limits
	for _, key := range keys {
		if err := r.checkLimit(ctx, key, tier); err != nil {
			return r.handleLimitExceeded(ctx, reqCtx, err)
		}
	}

	// Check quota if configured
	if r.quota != nil {
		if err := r.checkQuota(ctx, reqCtx); err != nil {
			return r.handleLimitExceeded(ctx, reqCtx, err)
		}
	}

	// Add rate limit headers
	r.addRateLimitHeaders(reqCtx, tier)

	return nil
}

func (r *RateLimiter) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	// Update dynamic limits based on response
	if r.dynamic != nil && r.dynamic.AutoScale {
		r.updateDynamicLimits(respCtx)
	}
	return nil
}

// Helper methods

func (r *RateLimiter) getTierForRequest(reqCtx *plugins.RequestContext) RateLimitTier {
	// Check for tier in request metadata or headers
	tierName := r.defaultTier
	if tier, exists := reqCtx.Metadata["tier"].(string); exists {
		if t, ok := r.tiers[tier]; ok {
			return t
		}
	}
	return r.tiers[tierName]
}

func (r *RateLimiter) buildRateLimitKeys(reqCtx *plugins.RequestContext, tier RateLimitTier) []string {
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

func (r *RateLimiter) checkQuota(ctx context.Context, reqCtx *plugins.RequestContext) error {
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

func (r *RateLimiter) handleLimitExceeded(ctx context.Context, reqCtx *plugins.RequestContext, err error) error {
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

func (r *RateLimiter) addRateLimitHeaders(reqCtx *plugins.RequestContext, tier RateLimitTier) {
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Limit", strconv.Itoa(tier.Limit))
	reqCtx.ForwardRequest.Header.Set("X-RateLimit-Window", tier.Window.String())
	if r.actions != nil && r.actions.RetryAfter != "" {
		reqCtx.ForwardRequest.Header.Set("Retry-After", r.actions.RetryAfter)
	}
}

func (r *RateLimiter) updateDynamicLimits(respCtx *plugins.ResponseContext) {
	if respCtx.Response.StatusCode >= 500 {
		r.mu.Lock()
		defer r.mu.Unlock()

		// Reduce limits temporarily
		for _, tier := range r.tiers {
			tier.Limit = int(float64(tier.Limit) * r.dynamic.LoadFactor)
		}
	}
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

func (r *RateLimiter) sendNotification(ctx context.Context, reqCtx *plugins.RequestContext, err error) {
	notification := map[string]interface{}{
		"tenant_id": reqCtx.TenantID,
		"path":      reqCtx.OriginalRequest.URL.Path,
		"error":     err.Error(),
		"timestamp": time.Now(),
	}

	payload, _ := json.Marshal(notification)
	http.Post(r.actions.NotificationWebhook, "application/json", bytes.NewReader(payload))
}
