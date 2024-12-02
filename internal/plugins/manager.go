package plugins

import (
	"fmt"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

type PluginManager struct {
	factory *PluginFactory
	plugins map[string]Plugin
	logger  *logrus.Logger
	mu      sync.RWMutex
}

func NewPluginManager(logger *logrus.Logger, redisClient *redis.Client) *PluginManager {
	return &PluginManager{
		factory: NewPluginFactory(logger, redisClient),
		plugins: make(map[string]Plugin),
		logger:  logger,
	}
}

func (m *PluginManager) GetOrCreatePlugin(name string, config map[string]interface{}) (Plugin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, exists := m.plugins[name]; exists {
		return p, nil
	}

	plugin, err := m.factory.CreatePlugin(name, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create plugin %s: %w", name, err)
	}

	m.plugins[name] = plugin
	return plugin, nil
}

func (m *PluginManager) GetPlugin(name string) (Plugin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.plugins[name]
	return p, exists
}
