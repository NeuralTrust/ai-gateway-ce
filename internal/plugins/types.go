package plugins

import (
	"ai-gateway-ce/internal/types"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

// PluginContext holds the context for plugin execution
type PluginContext struct {
	Config   types.PluginConfig
	Redis    *redis.Client
	Logger   *logrus.Logger
	Metadata map[string]interface{}
}

// BasePlugin provides common functionality for all plugins
type BasePlugin struct {
	name   string
	logger *logrus.Logger
}

func (p *BasePlugin) GetName() string {
	return p.name
}
