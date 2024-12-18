package plugins

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/pluginiface"
	"ai-gateway-ce/pkg/plugins/external_api"
	"ai-gateway-ce/pkg/plugins/rate_limiter"
	"ai-gateway-ce/pkg/types"
)

type PluginFactory struct {
	cache  *cache.Cache
	logger *logrus.Logger
}

func NewPluginFactory(cache *cache.Cache, logger *logrus.Logger) *PluginFactory {
	return &PluginFactory{
		cache:  cache,
		logger: logger,
	}
}

func (f *PluginFactory) CreatePlugin(name string) (pluginiface.Plugin, error) {
	switch name {
	case "rate_limiter":
		return rate_limiter.NewRateLimiterPlugin(f.cache.Client()), nil
	case "external_api":
		return external_api.NewExternalApiPlugin(), nil
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}
}

type PluginValidator interface {
	ValidateConfig(config types.PluginConfig) error
}

func (f *PluginFactory) GetValidator(name string) (PluginValidator, error) {
	switch name {
	case "rate_limiter":
		return &rate_limiter.RateLimiterValidator{}, nil
	case "external_api":
		return &external_api.ExternalApiValidator{}, nil
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}
}
