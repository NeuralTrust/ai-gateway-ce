package plugins

import (
	"fmt"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/internal/plugins/external"
	"ai-gateway-ce/internal/plugins/rate_limiter"
	"ai-gateway-ce/internal/types"
)

type Factory struct {
	redis  *redis.Client
	logger *logrus.Logger
	cache  sync.Map // map[string]types.Plugin
}

func NewFactory(logger *logrus.Logger, redisClient *redis.Client) *Factory {
	return &Factory{
		logger: logger,
		redis:  redisClient,
	}
}

func (f *Factory) CreatePlugin(name string, config types.PluginConfig) (types.Plugin, error) {
	// Check cache first
	if plugin, ok := f.cache.Load(name); ok {
		if err := plugin.(types.Plugin).Configure(config); err != nil {
			return nil, err
		}
		return plugin.(types.Plugin), nil
	}

	var plugin types.Plugin

	switch name {
	case "rate_limiter":
		plugin = rate_limiter.NewRateLimiter(f.redis, f.logger)
	case "external_validator":
		validator, err := external.NewExternalValidator(f.logger, config)
		if err != nil {
			f.logger.WithError(err).Error("Failed to create external validator")
			return nil, err
		}
		plugin = validator
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}

	if err := plugin.Configure(config); err != nil {
		return nil, err
	}

	// Cache the plugin instance
	f.cache.Store(name, plugin)
	return plugin, nil
}
