package types

import (
	"sync"
	"time"
)

// TTLEntry represents a cached entry with expiration
type TTLEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// TTLMap represents a thread-safe map with TTL
type TTLMap struct {
	Mu   sync.RWMutex
	Data map[string]*TTLEntry
	TTL  time.Duration
}

// CacheKeys holds the standard cache key formats
type CacheKeys struct {
	Gateway string
	Rules   string
	Plugin  string
}

// CacheConfig holds Redis configuration
type CacheConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}
