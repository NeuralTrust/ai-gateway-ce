package blacklist

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

type Blacklist struct {
	mu          sync.RWMutex
	blockedIPs  map[string]bool
	blockedPath map[string]bool
}

type Config struct {
	BlockedIPs   []string `json:"blocked_ips"`
	BlockedPaths []string `json:"blocked_paths"`
}

func NewBlacklist(config Config) *Blacklist {
	blockedIPs := make(map[string]bool)
	for _, ip := range config.BlockedIPs {
		blockedIPs[ip] = true
	}

	blockedPaths := make(map[string]bool)
	for _, path := range config.BlockedPaths {
		blockedPaths[path] = true
	}

	return &Blacklist{
		blockedIPs:  blockedIPs,
		blockedPath: blockedPaths,
	}
}

func (b *Blacklist) Name() string {
	return "blacklist"
}

func (b *Blacklist) Priority() int {
	return 50
}

func (b *Blacklist) ProcessRequest(ctx context.Context, req *http.Request) error {
	ip := req.RemoteAddr
	path := req.URL.Path

	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.blockedIPs[ip] {
		return fmt.Errorf("IP address %s is blacklisted", ip)
	}

	if b.blockedPath[path] {
		return fmt.Errorf("path %s is blacklisted", path)
	}

	return nil
}

func (b *Blacklist) ProcessResponse(ctx context.Context, resp *http.Response) error {
	return nil
}
