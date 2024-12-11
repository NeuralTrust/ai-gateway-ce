package plugins

import (
	"ai-gateway-ce/internal/types"
	"sort"
	"sync"
)

// Registry manages plugin registration and lookup
type Registry struct {
	plugins map[string]types.Plugin
	mu      sync.RWMutex // For thread-safe access
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]types.Plugin),
	}
}

// RegisterPlugin registers a plugin with the registry
func (r *Registry) RegisterPlugin(name string, plugin types.Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[name] = plugin
	return nil
}

// GetPlugin retrieves a plugin by name
func (r *Registry) GetPlugin(name string) (types.Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, ok := r.plugins[name]
	return plugin, ok
}

// pluginExecution holds plugin and its configuration for execution
type pluginExecution struct {
	plugin types.Plugin
	config types.PluginConfig
}

// ExecutePlugins executes a chain of plugins based on priority
func (r *Registry) ExecutePlugins(ctx *types.RequestContext, configs []types.PluginConfig) error {
	// Group plugins by priority
	priorityGroups := make(map[int][]pluginExecution)

	// Collect and group plugins by priority
	for _, config := range configs {
		plugin, exists := r.GetPlugin(config.Name)
		if !exists {
			continue
		}
		priority := plugin.Priority()
		priorityGroups[priority] = append(priorityGroups[priority], pluginExecution{
			plugin: plugin,
			config: config,
		})
	}

	// Get sorted priorities
	var priorities []int
	for priority := range priorityGroups {
		priorities = append(priorities, priority)
	}
	sort.Ints(priorities)

	// Execute plugins in priority order
	for _, priority := range priorities {
		plugins := priorityGroups[priority]

		// If there's only one plugin at this priority, execute it sequentially
		if len(plugins) == 1 {
			if err := plugins[0].plugin.ProcessRequest(ctx, &types.ResponseContext{}); err != nil {
				return err
			}
			continue
		}

		// Multiple plugins at same priority can run in parallel
		var wg sync.WaitGroup
		errChan := make(chan error, len(plugins))

		for _, p := range plugins {
			wg.Add(1)
			go func(pe pluginExecution) {
				defer wg.Done()
				if err := pe.plugin.ProcessRequest(ctx, &types.ResponseContext{}); err != nil {
					errChan <- err
				}
			}(p)
		}

		// Wait for all parallel plugins to complete
		wg.Wait()
		close(errChan)

		// Check for any errors from parallel execution
		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	return nil
}
