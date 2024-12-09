package plugins

import (
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/internal/plugins/external"
	"ai-gateway-ce/internal/plugins/rate_limiter"
	"ai-gateway-ce/internal/types"
)

type Factory struct {
	logger      *logrus.Logger
	redisClient *redis.Client
}

func NewFactory(logger *logrus.Logger, redisClient *redis.Client) *Factory {
	return &Factory{
		logger:      logger,
		redisClient: redisClient,
	}
}

func (f *Factory) CreatePlugin(name string, config types.PluginConfig) (types.Plugin, error) {
	f.logger.WithFields(logrus.Fields{
		"plugin": name,
		"config": config,
	}).Debug("Creating plugin")

	var plugin types.Plugin

	switch name {
	case "rate_limiter":
		limiter := rate_limiter.NewRateLimiter(f.redisClient, f.logger)
		if err := limiter.Configure(config); err != nil {
			f.logger.WithError(err).Error("Failed to configure rate limiter")
			return nil, err
		}
		plugin = limiter
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

	f.logger.WithField("plugin", name).Debug("Created plugin")
	return plugin, nil
}
