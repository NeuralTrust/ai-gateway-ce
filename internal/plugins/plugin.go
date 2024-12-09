package plugins

import (
	"ai-gateway-ce/internal/types"
)

// PluginManagerInterface defines the plugin management operations
type PluginManagerInterface interface {
	RegisterPlugin(name string, plugin types.Plugin) error
	GetPlugin(name string) (types.Plugin, bool)
}

// PluginManager implements the PluginManagerInterface
type PluginManager struct {
	registry *Registry
}

// NewPluginManager creates a new plugin manager
func NewPluginManager() *PluginManager {
	return &PluginManager{
		registry: NewRegistry(),
	}
}

// RegisterPlugin registers a plugin with the manager
func (pm *PluginManager) RegisterPlugin(name string, plugin types.Plugin) error {
	return pm.registry.RegisterPlugin(name, plugin)
}

// GetPlugin retrieves a plugin by name
func (pm *PluginManager) GetPlugin(name string) (types.Plugin, bool) {
	return pm.registry.GetPlugin(name)
}
