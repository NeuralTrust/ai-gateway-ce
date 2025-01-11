package server

import (
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/ai-gateway-ce/pkg/cache"
	"github.com/NeuralTrust/ai-gateway-ce/pkg/config"
	"github.com/NeuralTrust/ai-gateway-ce/pkg/database"
)

// Server interface defines the common behavior for all servers
type Server interface {
	Run() error
}

type BaseServer struct {
	config *config.Config
	cache  *cache.Cache
	repo   *database.Repository
	logger *logrus.Logger
	router *gin.Engine
}

func init() {
	// Set Gin mode to release by default
	gin.SetMode(gin.ReleaseMode)
	// Disable Gin's default logging globally
	gin.DefaultWriter = io.Discard
}

func NewBaseServer(config *config.Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *BaseServer {
	// Create a new Gin router with default middleware
	router := gin.New()

	// Disable all Gin logging middleware
	router.Use(gin.Recovery())

	return &BaseServer{
		config: config,
		cache:  cache,
		repo:   repo,
		logger: logger,
		router: router,
	}
}

// setupHealthCheck adds a health check endpoint to the server
func (s *BaseServer) setupHealthCheck() {
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})
}

// isProxyServer returns true if this is a proxy server instance
func (s *BaseServer) isProxyServer() bool {
	return false // Base implementation returns false
}

// runServer is a helper method to start the server
func (s *BaseServer) runServer(addr string) error {
	// Only set up health check if this isn't a proxy server
	if !s.isProxyServer() {
		s.setupHealthCheck()
	}
	return s.router.Run(addr)
}
