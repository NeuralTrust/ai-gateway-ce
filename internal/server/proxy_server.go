package server

import (
	"ai-gateway-ce/internal/cache"
	"ai-gateway-ce/internal/database"
	"fmt"

	"github.com/sirupsen/logrus"
)

type ProxyServer struct {
	*BaseServer
	pipeline *RequestPipeline
}

func NewProxyServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *ProxyServer {
	server := &ProxyServer{
		BaseServer: NewBaseServer(config, cache, repo, logger),
		pipeline:   NewRequestPipeline(100, 1000), // Configure workers and batch size
	}
	server.pipeline.Start()
	return server
}

func (s *ProxyServer) Run() error {
	s.setupHealthCheck()
	return s.router.Run(fmt.Sprintf(":%d", s.config.ProxyPort))
}

// ... existing code ...
