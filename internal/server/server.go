package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/database"
)

// Server interface defines the common behavior for all servers
type Server interface {
	Run() error
}

type BaseServer struct {
	config *Config
	cache  *cache.Cache
	repo   *database.Repository
	logger *logrus.Logger
	router *gin.Engine
}

func init() {
	// Set Gin mode to release by default
	gin.SetMode(gin.ReleaseMode)
}

func NewBaseServer(config *Config, cache *cache.Cache, repo *database.Repository, logger *logrus.Logger) *BaseServer {
	// Create a new Gin router with default middleware
	router := gin.New()
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
