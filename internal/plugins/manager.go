package plugins

import (
	"fmt"
	"reflect"
	"sync"

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
		if !config.Enabled {
			continue
		}

		m.logger.WithFields(logrus.Fields{
			"plugin":   config.Name,
			"settings": config.Settings,
		}).Debug("Executing serial plugin")

		plugin, err := m.GetOrCreatePlugin(config.Name, config)
		if err != nil {
			return err
		}

		if err := m.executePlugin(plugin, ctx); err != nil {
			if pluginErr, ok := err.(*types.PluginError); ok {
				m.logger.WithFields(logrus.Fields{
					"plugin":      config.Name,
					"status_code": pluginErr.StatusCode,
					"message":     pluginErr.Message,
				}).Warn("Plugin error")
				return err
			}
			if reqCtx, ok := ctx.(*types.RequestContext); ok && reqCtx.StopForwarding {
				m.logger.WithError(err).Warn("Plugin requested to stop forwarding")
				return err
			}
			m.logger.WithError(err).Error("Plugin execution error")
			return err
		}
	}

	// Execute parallel plugins only if no serial plugin stopped the flow
	if reqCtx, ok := ctx.(*types.RequestContext); ok && reqCtx.StopForwarding {
		return fmt.Errorf("request forwarding stopped by plugin")
	}

	// Execute parallel plugins
	if len(parallelPlugins) > 0 {
		errChan := make(chan error, len(parallelPlugins))
		var wg sync.WaitGroup

		for _, config := range parallelPlugins {
			if !config.Enabled {
				continue
			}

			wg.Add(1)
			go func(pc types.PluginConfig) {
				defer wg.Done()

				m.logger.WithFields(logrus.Fields{
					"plugin":   pc.Name,
					"settings": pc.Settings,
				}).Debug("Executing parallel plugin")

				plugin, err := m.GetOrCreatePlugin(pc.Name, pc)
				if err != nil {
					errChan <- err
					return
				}

				if err := m.executePlugin(plugin, ctx); err != nil {
					errChan <- err
					return
				}
			}(config)
		}

		// Wait for all parallel plugins to complete
		wg.Wait()
		close(errChan)

		// Check for any errors from parallel plugins
		for err := range errChan {
			if err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					m.logger.WithFields(logrus.Fields{
						"status_code": pluginErr.StatusCode,
						"message":     pluginErr.Message,
					}).Warn("Parallel plugin error")
					return err
				}
				m.logger.WithError(err).Error("Parallel plugin execution error")
				return err
			}
		}
	}

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

func (m *Manager) ValidatePluginConfig(plugins interface{}) (interface{}, error) {
	// If plugins is nil or empty bytes, return empty object
	if plugins == nil || (reflect.TypeOf(plugins).Kind() == reflect.Slice && reflect.ValueOf(plugins).Len() == 0) {
		return map[string]interface{}{}, nil
	}

	// Add proper validation for plugins data
	// Return cleaned/validated plugins configuration
	return plugins, nil
}
