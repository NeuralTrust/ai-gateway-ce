package cache

import (
	"ai-gateway-ce/pkg/types"
	"sync"
	"time"
)

// TTLMap wraps types.TTLMap to add methods
type TTLMap struct {
	*types.TTLMap
}

func NewTTLMap(ttl time.Duration) *TTLMap {
	return &TTLMap{
		TTLMap: &types.TTLMap{
			Mu:   sync.RWMutex{},
			Data: make(map[string]*types.TTLEntry),
			TTL:  ttl,
		},
	}
}

func (m *TTLMap) Get(key string) (interface{}, bool) {
	m.Mu.RLock()
	defer m.Mu.RUnlock()

	entry, exists := m.Data[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		delete(m.Data, key)
		return nil, false
	}
	return entry.Value, true
}

func (m *TTLMap) Set(key string, value interface{}) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	m.Data[key] = &types.TTLEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(m.TTL),
	}
}

func (m *TTLMap) Delete(key string) {
	m.Mu.Lock()
	defer m.Mu.Unlock()
	delete(m.Data, key)
}
