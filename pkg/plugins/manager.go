package plugins

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
)

type Manager struct {
	mu             sync.RWMutex
	factory        *PluginFactory
	plugins        map[string]types.Plugin
	configurations map[types.Level]map[string][]types.PluginConfig
}

func NewManager(factory *PluginFactory) *Manager {
	return &Manager{
		factory:        factory,
		plugins:        make(map[string]types.Plugin),
		configurations: make(map[types.Level]map[string][]types.PluginConfig),
	}
}

func (m *Manager) RegisterPlugin(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if plugin is already registered
	if _, exists := m.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	// Create plugin using factory
	plugin, err := m.factory.CreatePlugin(name)
	if err != nil {
		return fmt.Errorf("failed to create plugin %s: %w", name, err)
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

func (m *Manager) ExecuteStage(ctx context.Context, stage types.Stage, gatewayID, ruleID string, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
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
		logger.WithFields(logrus.Fields{
			"stage":     stage,
			"gatewayID": gatewayID,
			"chains":    len(gatewayChains),
		}).Debug("Executing gateway-level plugins")

		pluginResp, err := m.executeChains(ctx, plugins, gatewayChains, req, resp)
		if err != nil {
			return nil, err
		}
		if pluginResp != nil {
			return pluginResp, nil
		}
	}

	// Then execute rule-level chains
	if len(ruleChains) > 0 {
		logger.WithFields(logrus.Fields{
			"stage":  stage,
			"ruleID": ruleID,
			"chains": len(ruleChains),
		}).Debug("Executing rule-level plugins")

		return m.executeChains(ctx, plugins, ruleChains, req, resp)
	}

	return nil, nil
}

func (m *Manager) executeChains(ctx context.Context, plugins map[string]types.Plugin, chains []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	for _, chain := range chains {
		if chain.Parallel {
			if err := m.executeParallel(ctx, plugins, []types.PluginConfig{chain}, req, resp); err != nil {
				return nil, err
			}
		} else {
			pluginResp, err := m.executeSequential(ctx, plugins, []types.PluginConfig{chain}, req, resp)
			if err != nil {
				return nil, err
			}
			if pluginResp != nil {
				return pluginResp, nil
			}
		}
	}
	return nil, nil
}

func (m *Manager) executeParallel(ctx context.Context, plugins map[string]types.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
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

		// Create error channel and wait group for this priority group
		errChan := make(chan error, len(group))
		var wg sync.WaitGroup

		// Launch all plugins in this priority group in parallel
		for _, cfg := range group {
			wg.Add(1)
			go func(cfg types.PluginConfig) {
				defer wg.Done()
				if plugin, exists := plugins[cfg.Name]; exists {
					pluginResp, err := plugin.Execute(ctx, cfg, req, resp)
					if err != nil {
						errChan <- err
					}
					if pluginResp != nil {
						// Handle plugin response
						resp.StatusCode = pluginResp.StatusCode
						resp.Body = []byte(pluginResp.Message)
					}
				}
			}(cfg)
		}

		// Wait for all plugins in this priority group to complete
		wg.Wait()
		close(errChan)

		// Check for errors from this priority group
		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *Manager) executeSequential(ctx context.Context, plugins map[string]types.Plugin, configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	// Sort by priority
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
				return nil, err
			}
			if pluginResp != nil {
				// Return plugin response directly
				return pluginResp, nil
			}
		}
	}
	return nil, nil
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

func (m *Manager) ExecutePlugins(configs []types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
	// Convert RequestContext to Request
	request := &types.RequestContext{
		Context: req.Context,
		Headers: req.Headers,
		Method:  req.Method,
		Path:    req.Path,
		Query:   req.Query,
		Body:    req.Body,
	}

	// Convert ResponseContext to Response
	response := &types.ResponseContext{
		Headers: resp.Headers,
		Body:    resp.Body,
	}

	// Execute plugins
	for _, cfg := range configs {
		if plugin, exists := m.plugins[cfg.Name]; exists {
			if _, err := plugin.Execute(req.Context, cfg, request, response); err != nil {
				return err
			}
		}
	}

	// Update response context
	resp.Headers = response.Headers
	resp.Body = response.Body
	resp.Metadata["status_code"] = response.StatusCode

	return nil
}

func (m *Manager) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) error {
	plugin, err := m.factory.CreatePlugin(cfg.Name)
	if err != nil {
		return fmt.Errorf("failed to create plugin %s: %w", cfg.Name, err)
	}

	logger := ctx.Value("logger").(*logrus.Logger)
	logger.WithFields(logrus.Fields{
		"plugin": cfg.Name,
		"stage":  cfg.Stage,
		"level":  cfg.Level,
	}).Debug("Executing plugin")

	_, err = plugin.Execute(ctx, cfg, req, resp)
	if err != nil {
		return err
	}
	return nil
}
