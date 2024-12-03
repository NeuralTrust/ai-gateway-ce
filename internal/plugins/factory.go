package plugins

import (
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/plugins/external"
	"ai-gateway/internal/plugins/rate_limiter"
	"ai-gateway/internal/types"
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

func (f *Factory) CreatePlugin(name string, config types.PluginConfig) (Plugin, error) {
	f.logger.WithFields(logrus.Fields{
		"plugin": name,
		"config": config,
	}).Debug("Creating plugin")

	switch name {
	case "rate_limiter":
		return rate_limiter.NewRateLimiter(f.redisClient, f.logger, config)
	case "external_validator":
		validator, err := external.NewExternalValidator(f.logger, config)
		if err != nil {
			f.logger.WithError(err).Error("Failed to create external validator")
			return nil, err
		}
		f.logger.Debug("Created external validator")
		return validator, nil
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}
}
