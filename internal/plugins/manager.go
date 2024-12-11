package plugins

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/internal/types"
)

type pluginKey struct {
	name   string
	config string // JSON representation of config
}

type Manager struct {
	logger  *logrus.Logger
	redis   *redis.Client
	plugins map[pluginKey]types.Plugin
	factory *Factory
	mu      sync.RWMutex
}

func NewManager(logger *logrus.Logger, redis *redis.Client) *Manager {
	return &Manager{
		logger:  logger,
		redis:   redis,
		plugins: make(map[pluginKey]types.Plugin),
		factory: NewFactory(logger, redis),
	}
}

func (m *Manager) getPlugin(name string, config types.PluginConfig) (types.Plugin, error) {
	// Create a unique key for this plugin configuration
	configJSON, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plugin config: %w", err)
	}
	key := pluginKey{name: name, config: string(configJSON)}

	m.mu.RLock()
	if plugin, exists := m.plugins[key]; exists {
		m.mu.RUnlock()
		return plugin, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check again in case another goroutine created it
	if plugin, exists := m.plugins[key]; exists {
		return plugin, nil
	}

	// Create and configure new plugin
	plugin, err := m.factory.CreatePlugin(name, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin %s: %w", name, err)
	}

	if err := plugin.Configure(config); err != nil {
		return nil, fmt.Errorf("failed to configure plugin %s: %w", name, err)
	}

	m.plugins[key] = plugin
	return plugin, nil
}

func (m *Manager) executePlugin(plugin types.Plugin, config types.PluginConfig, reqCtx *types.RequestContext, respCtx *types.ResponseContext) error {
	// Execute plugin based on its stage
	switch config.Stage {
	case "pre_request":
		if reqCtx != nil {
			if err := plugin.ProcessRequest(reqCtx, respCtx); err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					return pluginErr
				}
				return fmt.Errorf("plugin %s error: %w", config.Name, err)
			}
		}
	case "post_request":
		if reqCtx != nil {
			if err := plugin.ProcessRequest(reqCtx, respCtx); err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					return pluginErr
				}
				return fmt.Errorf("plugin %s error: %w", config.Name, err)
			}
		}
	case "pre_response", "post_response":
		if respCtx != nil && respCtx.Response != nil {
			if err := plugin.ProcessResponse(respCtx); err != nil {
				if pluginErr, ok := err.(*types.PluginError); ok {
					return pluginErr
				}
				return fmt.Errorf("plugin %s error: %w", config.Name, err)
			}
		}
	}
	return nil
}

func (m *Manager) ExecutePlugins(pluginChain []types.PluginConfig, reqCtx *types.RequestContext, respCtx *types.ResponseContext) error {
	if len(pluginChain) == 0 {
		return nil
	}

	// Sort plugins by priority and stage
	sort.SliceStable(pluginChain, func(i, j int) bool {
		if pluginChain[i].Stage != pluginChain[j].Stage {
			return pluginChain[i].Stage < pluginChain[j].Stage
		}
		return pluginChain[i].Priority < pluginChain[j].Priority
	})

	// Group plugins by stage
	stageGroups := make(map[string][]types.PluginConfig)
	for _, plugin := range pluginChain {
		if !plugin.Enabled {
			continue
		}
		stageGroups[plugin.Stage] = append(stageGroups[plugin.Stage], plugin)
	}

	// Execute plugins in stage order
	stages := []string{"pre_request", "post_request", "pre_response", "post_response"}
	for _, stage := range stages {
		plugins := stageGroups[stage]
		if len(plugins) == 0 {
			continue
		}

		// Group plugins by parallel capability
		var serialPlugins, parallelPlugins []types.PluginConfig
		for _, p := range plugins {
			if p.Parallel {
				parallelPlugins = append(parallelPlugins, p)
			} else {
				serialPlugins = append(serialPlugins, p)
			}
		}

		// Execute parallel plugins
		if len(parallelPlugins) > 0 {
			var wg sync.WaitGroup
			errChan := make(chan error, len(parallelPlugins))

			for _, p := range parallelPlugins {
				wg.Add(1)
				go func(config types.PluginConfig) {
					defer wg.Done()
					plugin, err := m.getPlugin(config.Name, config)
					if err != nil {
						errChan <- fmt.Errorf("plugin %s error: %w", config.Name, err)
						return
					}

					if err := m.executePlugin(plugin, config, reqCtx, respCtx); err != nil {
						// Don't wrap PluginError to preserve status code
						if pluginErr, ok := err.(*types.PluginError); ok {
							errChan <- pluginErr
						} else {
							errChan <- fmt.Errorf("plugin %s error: %w", config.Name, err)
						}
					}
					if respCtx.Metadata == nil {
						respCtx.Metadata = make(map[string]interface{})
					}
					for k, v := range respCtx.Metadata {
						respCtx.Metadata[k] = v
					}
				}(p)
			}

			// Wait for all parallel plugins to complete
			wg.Wait()
			close(errChan)

			// Check for errors
			for err := range errChan {
				if err != nil {
					return err
				}
			}
		}

		// Execute serial plugins
		for _, config := range serialPlugins {
			plugin, err := m.getPlugin(config.Name, config)
			if err != nil {
				return fmt.Errorf("plugin %s error: %w", config.Name, err)
			}

			if err := m.executePlugin(plugin, config, reqCtx, respCtx); err != nil {
				return err
			}
		}
	}

	return nil
}
