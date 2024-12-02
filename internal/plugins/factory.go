package plugins

import (
	"fmt"
	"time"

	"ai-gateway/internal/plugins/rate_limiter"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type PluginFactory struct {
	logger      *logrus.Logger
	redisClient *redis.Client
}

func NewPluginFactory(logger *logrus.Logger, redisClient *redis.Client) *PluginFactory {
	return &PluginFactory{
		logger:      logger,
		redisClient: redisClient,
	}
}

func (f *PluginFactory) CreatePlugin(name string, config map[string]interface{}) (Plugin, error) {
	switch name {
	case "rate_limiter":
		return f.createRateLimiter(config)
	case "content_validator":
		return f.createContentValidator(config)
	case "security_validator":
		return f.createSecurityValidator(config)
	case "external_validator":
		return f.createExternalValidator(config)
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}
}

func (f *PluginFactory) createRateLimiter(config map[string]interface{}) (Plugin, error) {
	// Create default tier based on config
	window := "1m"
	if w, ok := config["window"].(string); ok {
		window = w
	}

	limit := 5
	if l, ok := config["limit"].(float64); ok {
		limit = int(l)
	}

	burst := 0
	if b, ok := config["burst"].(float64); ok {
		burst = int(b)
	}

	windowDuration, err := time.ParseDuration(window)
	if err != nil {
		return nil, fmt.Errorf("invalid window duration: %w", err)
	}

	// Create rate limiter config
	rlConfig := rate_limiter.Config{
		RedisClient: f.redisClient,
		Tiers: map[string]rate_limiter.RateLimitTier{
			"default": {
				Name:     "default",
				Limit:    limit,
				Window:   windowDuration,
				Burst:    burst,
				Priority: 1,
			},
		},
		DefaultTier: "default",
		LimitTypes: rate_limiter.RateLimitType{
			Global: true,
		},
	}

	return rate_limiter.NewRateLimiter(rlConfig, f.logger)
}

func (f *PluginFactory) createContentValidator(config map[string]interface{}) (Plugin, error) {
	// Implementation for content validator creation
	return nil, fmt.Errorf("not implemented")
}

func (f *PluginFactory) createSecurityValidator(config map[string]interface{}) (Plugin, error) {
	// Implementation for security validator creation
	return nil, fmt.Errorf("not implemented")
}

func (f *PluginFactory) createExternalValidator(config map[string]interface{}) (Plugin, error) {
	// Implementation for external validator creation
	return nil, fmt.Errorf("not implemented")
}
