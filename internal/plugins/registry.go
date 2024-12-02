package plugins

import (
	"fmt"
	"sync"
)

type Registry struct {
	factory *PluginFactory
	plugins map[string]Plugin
	mu      sync.RWMutex
}

func NewRegistry(factory *PluginFactory) *Registry {
	return &Registry{
		factory: factory,
		plugins: make(map[string]Plugin),
	}
}

// GetOrCreatePlugin gets an existing plugin or creates a new one
func (r *Registry) GetOrCreatePlugin(name string, config map[string]interface{}) (Plugin, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if plugin already exists
	if p, exists := r.plugins[name]; exists {
		return p, nil
	}

	// Create new plugin
	plugin, err := r.factory.CreatePlugin(name, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin %s: %w", name, err)
	}

	// Store plugin
	r.plugins[name] = plugin
	return plugin, nil
}

// GetPlugin gets an existing plugin
func (r *Registry) GetPlugin(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, exists := r.plugins[name]
	return p, exists
}
