package plugins

import (
	"fmt"

	"ai-gateway/internal/types"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	factory  *Factory
	registry *Registry
	logger   *logrus.Logger
}

func NewManager(logger *logrus.Logger, redisClient *redis.Client) *Manager {
	return &Manager{
		factory:  NewFactory(logger, redisClient),
		registry: NewRegistry(),
		logger:   logger,
	}
}

func (m *Manager) GetOrCreatePlugin(name string, config types.PluginConfig) (Plugin, error) {
	m.logger.WithFields(logrus.Fields{
		"plugin": name,
	}).Debug("Getting or creating plugin")

	if plugin, exists := m.registry.GetPlugin(name); exists {
		return plugin, nil
	}

	plugin, err := m.factory.CreatePlugin(name, config)
	if err != nil {
		return nil, err
	}

	if err := m.registry.RegisterPlugin(name, plugin); err != nil {
		return nil, err
	}

	return plugin, nil
}

func (m *Manager) ExecutePlugins(plugins []types.PluginConfig, ctx interface{}) error {
	var serialPlugins, parallelPlugins []types.PluginConfig
	for _, pc := range plugins {
		if pc.Parallel {
			parallelPlugins = append(parallelPlugins, pc)
		} else {
			serialPlugins = append(serialPlugins, pc)
		}
	}

	// Execute serial plugins first
	for _, config := range serialPlugins {
		plugin, err := m.GetOrCreatePlugin(config.Name, config)
		if err != nil {
			return err
		}

		if err := m.executePlugin(plugin, ctx); err != nil {
			if reqCtx, ok := ctx.(*types.RequestContext); ok && reqCtx.StopForwarding {
				m.logger.WithError(err).Warn("Plugin requested to stop forwarding")
				return err
			}
			m.logger.WithError(err).Error("Plugin execution error, continuing request flow")
			continue
		}
	}

	// Execute parallel plugins only if no serial plugin stopped the flow
	if reqCtx, ok := ctx.(*types.RequestContext); ok && reqCtx.StopForwarding {
		return fmt.Errorf("request forwarding stopped by plugin")
	}

	// Rest of parallel plugins execution...
	return nil
}

func (m *Manager) executePlugin(plugin Plugin, ctx interface{}) error {
	switch v := ctx.(type) {
	case *types.RequestContext:
		return plugin.ProcessRequest(v.Ctx, v)
	case *types.ResponseContext:
		return plugin.ProcessResponse(v.Ctx, v)
	default:
		return fmt.Errorf("unknown context type")
	}
}
