package plugins

import (
	"sync"
)

type Registry struct {
	plugins map[string]Plugin
	mu      sync.RWMutex
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

func (r *Registry) GetPlugin(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, exists := r.plugins[name]
	return plugin, exists
}

func (r *Registry) RegisterPlugin(name string, plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[name] = plugin
	return nil
}
