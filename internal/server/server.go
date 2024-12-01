package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/middleware"
	"ai-gateway/internal/plugins"
	"ai-gateway/internal/proxy"
	"ai-gateway/internal/rules"
)

type Server struct {
	router        *gin.Engine
	cache         *cache.Cache
	logger        *logrus.Logger
	config        *Config
	pluginManager *plugins.Registry
}

type Config struct {
	Port       int    `mapstructure:"port"`
	BaseDomain string `mapstructure:"base_domain"`
}

func NewServer(config *Config, cache *cache.Cache, logger *logrus.Logger, pluginManager *plugins.Registry) *Server {
	router := gin.New()
	router.Use(gin.Recovery())

	server := &Server{
		router:        router,
		cache:         cache,
		logger:        logger,
		config:        config,
		pluginManager: pluginManager,
	}

	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	// Create proxy handler with plugin manager
	proxyHandler := proxy.NewProxy(s.cache, s.logger, s.pluginManager)

	// Add tenant middleware to all routes
	s.router.Use(middleware.TenantIdentification(s.config.BaseDomain))

	// Health check endpoint
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Admin API routes
	admin := s.router.Group("/api/v1")
	{
		admin.GET("/forwarding-rules", s.getForwardingRules)
		admin.POST("/forwarding-rules", s.createForwardingRule)
		admin.PUT("/forwarding-rules/:id", s.updateForwardingRule)
		admin.DELETE("/forwarding-rules/:id", s.deleteForwardingRule)
	}

	// Proxy all other requests
	s.router.NoRoute(proxyHandler.Handle)
}

func (s *Server) Run() error {
	s.logger.Info("Starting server on port ", s.config.Port)
	return s.router.Run(fmt.Sprintf(":%d", s.config.Port))
}

// Handler implementations
func (s *Server) getForwardingRules(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Get rules from cache
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := s.cache.Get(c, key)
	if err != nil {
		if err.Error() == "redis: nil" {
			c.JSON(http.StatusOK, []rules.ForwardingRule{})
			return
		}
		s.logger.WithError(err).Error("Failed to get forwarding rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get forwarding rules"})
		return
	}

	var forwardingRules []rules.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &forwardingRules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse rules"})
		return
	}

	c.JSON(http.StatusOK, forwardingRules)
}

func (s *Server) createForwardingRule(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	var req rules.CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the request
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default values
	stripPath := true
	if req.StripPath != nil {
		stripPath = *req.StripPath
	}

	preserveHost := false
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}

	retryAttempts := 0
	if req.RetryAttempts != nil {
		retryAttempts = *req.RetryAttempts
	}

	// Create new rule
	rule := rules.ForwardingRule{
		ID:            uuid.New().String(),
		TenantID:      tenantID.(string),
		Path:          req.Path,
		Target:        req.Target,
		Methods:       req.Methods,
		Headers:       req.Headers,
		StripPath:     stripPath,
		PreserveHost:  preserveHost,
		RetryAttempts: retryAttempts,
		Active:        true,
	}

	// Get existing rules
	key := fmt.Sprintf("rules:%s", tenantID)
	var forwardingRules []rules.ForwardingRule

	rulesJSON, err := s.cache.Get(c, key)
	if err != nil && err.Error() != "redis: nil" {
		s.logger.WithError(err).Error("Failed to get existing rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	if rulesJSON != "" {
		if err := json.Unmarshal([]byte(rulesJSON), &forwardingRules); err != nil {
			s.logger.WithError(err).Error("Failed to unmarshal rules")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
			return
		}
	}

	// Add new rule
	forwardingRules = append(forwardingRules, rule)

	// Save updated rules
	updatedJSON, err := json.Marshal(forwardingRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	if err := s.cache.Set(c, key, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updateForwardingRule(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ruleID := c.Param("id")
	var req rules.UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing rules
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := s.cache.Get(c, key)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	var forwardingRules []rules.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &forwardingRules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	// Find and update rule
	found := false
	for i := range forwardingRules {
		if forwardingRules[i].ID == ruleID && forwardingRules[i].TenantID == tenantID.(string) {
			if req.Path != "" {
				forwardingRules[i].Path = req.Path
			}
			if req.Target != "" {
				forwardingRules[i].Target = req.Target
			}
			if len(req.Methods) > 0 {
				forwardingRules[i].Methods = req.Methods
			}
			if req.Active != nil {
				forwardingRules[i].Active = *req.Active
			}
			found = true
			break
		}
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(forwardingRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	if err := s.cache.Set(c, key, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule updated successfully"})
}

func (s *Server) deleteForwardingRule(c *gin.Context) {
	tenantID, exists := c.Get(middleware.TenantContextKey)
	if !exists {
		s.logger.Error("Tenant ID not found in context")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	ruleID := c.Param("id")

	// Get existing rules
	key := fmt.Sprintf("rules:%s", tenantID)
	rulesJSON, err := s.cache.Get(c, key)
	if err != nil {
		s.logger.WithError(err).Error("Failed to get rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	var forwardingRules []rules.ForwardingRule
	if err := json.Unmarshal([]byte(rulesJSON), &forwardingRules); err != nil {
		s.logger.WithError(err).Error("Failed to unmarshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	// Find and remove rule
	found := false
	newRules := make([]rules.ForwardingRule, 0, len(forwardingRules))
	for _, rule := range forwardingRules {
		if rule.ID == ruleID && rule.TenantID == tenantID.(string) {
			found = true
			continue
		}
		newRules = append(newRules, rule)
	}

	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
		return
	}

	// Save updated rules
	updatedJSON, err := json.Marshal(newRules)
	if err != nil {
		s.logger.WithError(err).Error("Failed to marshal rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	if err := s.cache.Set(c, key, string(updatedJSON), 0); err != nil {
		s.logger.WithError(err).Error("Failed to save rules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rule deleted successfully"})
}
