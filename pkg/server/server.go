package server

import (
	"ai-gateway-ce/pkg/types"
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Server struct {
	plugins map[string]types.Plugin
	logger  *logrus.Logger
	router  *gin.Engine
	port    int
	config  *Config
}

func NewServer() *Server {
	gin.SetMode(gin.ReleaseMode)
	config := NewConfig()
	return &Server{
		plugins: make(map[string]types.Plugin),
		logger:  logrus.New(),
		router:  gin.Default(),
		port:    config.ProxyPort,
		config:  config,
	}
}

func NewServerWithConfig(config *Config) *Server {
	gin.SetMode(gin.ReleaseMode)
	return &Server{
		plugins: make(map[string]types.Plugin),
		logger:  logrus.New(),
		router:  gin.Default(),
		port:    config.ProxyPort,
		config:  config,
	}
}

func (s *Server) RegisterPlugin(name string, plugin types.Plugin) {
	if plugin == nil {
		s.logger.Warnf("Attempting to register nil plugin with name %s", name)
		return
	}
	s.plugins[name] = plugin
	s.logger.Infof("Registered plugin: %s", name)
}

func (s *Server) Start() error {
	// Create context for plugin execution
	ctx := context.Background()
	pluginCtx := &types.PluginContext{}

	// Sort plugins by priority
	priorityGroups := make(map[int][]types.Plugin)
	for _, plugin := range s.plugins {
		priority := plugin.Priority()
		priorityGroups[priority] = append(priorityGroups[priority], plugin)
	}

	// Get sorted priorities
	var priorities []int
	for priority := range priorityGroups {
		priorities = append(priorities, priority)
	}
	sort.Ints(priorities)

	// Initialize plugins in priority order
	for _, priority := range priorities {
		plugins := priorityGroups[priority]
		s.logger.Infof("Initializing priority %d plugins", priority)

		// If only one plugin at this priority, run sequentially
		if len(plugins) == 1 {
			plugin := plugins[0]
			s.logger.Infof("Running plugin sequentially: %s", plugin.Name())
			if err := s.executePlugin(ctx, plugin, pluginCtx); err != nil {
				return err
			}
			continue
		}

		// Multiple plugins at same priority can run in parallel
		var wg sync.WaitGroup
		errChan := make(chan error, len(plugins))

		for _, plugin := range plugins {
			if !plugin.Parallel() {
				s.logger.Infof("Running plugin sequentially: %s", plugin.Name())
				if err := s.executePlugin(ctx, plugin, pluginCtx); err != nil {
					return err
				}
				continue
			}

			wg.Add(1)
			go func(p types.Plugin) {
				defer wg.Done()
				s.logger.Infof("Running plugin in parallel: %s", p.Name())
				if err := s.executePlugin(ctx, p, pluginCtx); err != nil {
					errChan <- err
				}
			}(plugin)
		}

		// Wait for all parallel plugins to complete
		wg.Wait()
		close(errChan)

		// Check for any errors
		for err := range errChan {
			if err != nil {
				return err
			}
		}
	}

	// Add more debug logging
	s.logger.WithFields(logrus.Fields{
		"port":          s.port,
		"plugins_count": len(s.plugins),
	}).Debug("Starting server configuration")

	// Add health check endpoint
	s.router.GET("/health", func(c *gin.Context) {
		s.logger.Debug("Health check endpoint called")
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// Test endpoints
	s.router.GET("/api/v1/test", func(c *gin.Context) {
		s.logger.Debug("Test endpoint called")
		c.JSON(http.StatusOK, gin.H{
			"version": "ce",
			"message": "Hello from Community Edition",
		})
	})

	// Start HTTP server
	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Infof("Starting server on %s", addr)

	// Add error handling
	if err := s.router.Run(addr); err != nil {
		s.logger.WithError(err).Error("Failed to start server")
		return err
	}
	return nil
}

// executePlugin executes a single plugin
func (s *Server) executePlugin(ctx context.Context, plugin types.Plugin, pluginCtx *types.PluginContext) error {
	s.logger.Debugf("Executing plugin: %s (Stage: %v)", plugin.Name(), plugin.Stage())

	switch plugin.Stage() {
	case types.PreRequest:
		return plugin.ProcessRequest(&types.RequestContext{
			Context: ctx,
		}, pluginCtx)
	case types.PostRequest:
		return plugin.ProcessResponse(&types.ResponseContext{
			Context: ctx,
		}, pluginCtx)
	default:
		s.logger.Warnf("Unknown plugin stage: %v", plugin.Stage())
		return nil
	}
}
