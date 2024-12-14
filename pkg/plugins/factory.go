package plugins

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/plugins/external_validator"
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

func (f *PluginFactory) CreatePlugin(name string) (types.Plugin, error) {
	switch name {
	case "rate_limiter":
		return rate_limiter.New(f.cache.Client()), nil
	case "external_validator":
		return external_validator.New(), nil
	default:
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}
}
