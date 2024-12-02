package server

import (
	"net/http"

	"ai-gateway/internal/cache"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Server interface {
	Run() error
}

// Base server implementation
type BaseServer struct {
	router *gin.Engine
	cache  *cache.Cache
	logger *logrus.Logger
	config *Config
}

func NewBaseServer(config *Config, cache *cache.Cache, logger *logrus.Logger) *BaseServer {
	router := gin.New()
	router.Use(gin.Recovery())

	return &BaseServer{
		router: router,
		cache:  cache,
		logger: logger,
		config: config,
	}
}

// Health check endpoint for both servers
func (s *BaseServer) setupHealthCheck() {
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
}
