package plugins

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"ai-gateway-ce/pkg/pluginiface"
	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
)

type Manager struct {
	mu             sync.RWMutex
	factory        *PluginFactory
	plugins        map[string]pluginiface.Plugin
	configurations map[types.Level]map[string][]types.PluginConfig
}

func NewManager(factory *PluginFactory) *Manager {
	return &Manager{
		factory:        factory,
		plugins:        make(map[string]pluginiface.Plugin),
		configurations: make(map[types.Level]map[string][]types.PluginConfig),
	}
}

func (m *Manager) RegisterPlugin(plugin pluginiface.Plugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := plugin.Name()
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	m.plugins[name] = plugin
	return nil
}

func (m *Manager) SetPluginChain(level types.Level, entityID string, chains []types.PluginConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate all plugins exist
	for _, chain := range chains {
		if _, exists := m.plugins[chain.Name]; !exists {
			return fmt.Errorf("plugin %s not registered", chain.Name)
		}
	}

	if m.configurations[level] == nil {
		m.configurations[level] = make(map[string][]types.PluginConfig)
	}

	m.configurations[level][entityID] = chains
	return nil
}

func (m *Manager) ExecuteStage(ctx context.Context, stage types.Stage, gatewayID, ruleID string, req *types.RequestContext, resp *types.ResponseContext) (*types.ResponseContext, error) {
	m.mu.RLock()
	// Get both gateway and rule level chains
	gatewayChains := m.getChains(types.GatewayLevel, gatewayID, stage)
	ruleChains := m.getChains(types.RuleLevel, ruleID, stage)
	plugins := m.plugins
	m.mu.RUnlock()

	logger := ctx.Value("logger").(*logrus.Logger)
	logger.WithFields(logrus.Fields{
		"stage":         stage,
		"gatewayID":     gatewayID,
		"ruleID":        ruleID,
		"gatewayChains": len(gatewayChains),
		"ruleChains":    len(ruleChains),
	}).Debug("Executing plugin stage")

	// Execute gateway-level chains first
	if len(gatewayChains) > 0 {
		if err := m.executeChains(ctx, plugins, gatewayChains, req, resp); err != nil {
			return resp, err
		}
	}

	// Then execute rule-level chains
	if len(ruleChains) > 0 {
		if err := m.executeChains(ctx, plugins, ruleChains, req, resp); err != nil {
			return resp, err
		}
	}

	return resp, nil
}

func (m *Manager) executeChains(ctx context.Context, plugins map[string]pluginiface.Plugin, chains []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
	// Group parallel and sequential chains
	var parallelChains, sequentialChains []types.PluginConfig
	for _, chain := range chains {
		if chain.Parallel {
			parallelChains = append(parallelChains, chain)
		} else {
			sequentialChains = append(sequentialChains, chain)
		}
	}

	// Execute parallel chains first
	if len(parallelChains) > 0 {
		if err := m.executeParallel(ctx, plugins, parallelChains, req, resp); err != nil {
			return err
		}
	}

	// Then execute sequential chains
	if len(sequentialChains) > 0 {
		if err := m.executeSequential(ctx, plugins, sequentialChains, req, resp); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) executeParallel(ctx context.Context, plugins map[string]pluginiface.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
	// Group plugins by priority
	priorityGroups := make(map[int][]types.PluginConfig)
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		priorityGroups[cfg.Priority] = append(priorityGroups[cfg.Priority], cfg)
	}

	// Get sorted priorities
	priorities := make([]int, 0, len(priorityGroups))
	for p := range priorityGroups {
		priorities = append(priorities, p)
	}
	sort.Ints(priorities)

	// Execute plugins by priority groups
	for _, priority := range priorities {
		group := priorityGroups[priority]
		errChan := make(chan error, len(group))
		type pluginResult struct {
			config   types.PluginConfig
			response *types.PluginResponse
		}
		respChan := make(chan pluginResult, len(group))
		var wg sync.WaitGroup

		// Create a context with cancel for this priority group
		groupCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		for _, cfg := range group {
			wg.Add(1)
			go func(cfg types.PluginConfig) {
				defer wg.Done()
				select {
				case <-groupCtx.Done():
					return
				default:
					if plugin, exists := plugins[cfg.Name]; exists {
						pluginResp, err := plugin.Execute(ctx, cfg, req, resp)
						if err != nil {
							errChan <- err
							cancel() // Cancel other goroutines in this group
							return
						}
						respChan <- pluginResult{config: cfg, response: pluginResp}
					}
				}
			}(cfg)
		}

		wg.Wait()
		close(errChan)
		close(respChan)

		// Check for errors
		for err := range errChan {
			if err != nil {
				return err
			}
		}

		// Collect all responses
		var results []pluginResult
		for result := range respChan {
			results = append(results, result)
		}

		// Sort results by plugin priority
		sort.Slice(results, func(i, j int) bool {
			return results[i].config.Priority < results[j].config.Priority
		})

		// Apply responses in priority order
		for _, result := range results {
			if result.response != nil {
				m.mu.Lock()
				resp.StatusCode = result.response.StatusCode
				resp.Body = result.response.Body
				if result.response.Headers != nil {
					for k, v := range result.response.Headers {
						resp.Headers[k] = v
					}
				}
				if result.response.Metadata != nil {
					for k, v := range result.response.Metadata {
						resp.Metadata[k] = v
					}
				}
				m.mu.Unlock()
			}
		}
	}

	return nil
}

func (m *Manager) executeSequential(ctx context.Context, plugins map[string]pluginiface.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
	sortedConfigs := make([]types.PluginConfig, len(configs))
	copy(sortedConfigs, configs)
	sort.Slice(sortedConfigs, func(i, j int) bool {
		return sortedConfigs[i].Priority < sortedConfigs[j].Priority
	})

	for _, cfg := range sortedConfigs {
		if !cfg.Enabled {
			continue
		}

		if plugin, exists := plugins[cfg.Name]; exists {
			pluginResp, err := plugin.Execute(ctx, cfg, req, resp)
			if err != nil {
				return err
			}
			if pluginResp != nil {
				resp.StatusCode = pluginResp.StatusCode
				if pluginResp.Body != nil {
					resp.Body = pluginResp.Body
				}
				if pluginResp.Headers != nil {
					for k, v := range pluginResp.Headers {
						resp.Headers[k] = v
					}
				}
				if pluginResp.Metadata != nil {
					for k, v := range pluginResp.Metadata {
						resp.Metadata[k] = v
					}
				}
			}
		}
	}
	return nil
}

func (m *Manager) getChains(level types.Level, entityID string, stage types.Stage) []types.PluginConfig {
	if configs, exists := m.configurations[level]; exists {
		if chains, exists := configs[entityID]; exists {
			var stageChains []types.PluginConfig
			for _, chain := range chains {
				if chain.Stage == stage {
					stageChains = append(stageChains, chain)
				}
			}
			return stageChains
		}
	}
	return nil
}
