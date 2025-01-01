package middleware

import (
	"context"
	"net/http"
	"strings"

	"ai-gateway-ce/pkg/database"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type AuthMiddleware struct {
	logger *logrus.Logger
	db     *database.Repository
}

func NewAuthMiddleware(logger *logrus.Logger, repo *database.Repository) *AuthMiddleware {
	return &AuthMiddleware{
		logger: logger,
		db:     repo,
	}
}

func (m *AuthMiddleware) ValidateAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for system endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/__/") {
			c.Next()
			return
		}

		// Extract API key from X-Api-Key header first, then fallback to Authorization header
		apiKey := c.GetHeader("X-Api-Key")
		if apiKey == "" {
			authHeader := c.GetHeader("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			m.logger.Debug("No API key provided")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		// Get gateway ID from context
		gatewayID, exists := c.Get(GatewayContextKey)
		if !exists {
			m.logger.Error("Gateway ID not found in context")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		// Validate API key
		valid, err := m.db.ValidateAPIKey(c.Request.Context(), gatewayID.(string), apiKey)
		if err != nil {
			m.logger.WithError(err).Error("Database error during API key validation")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
			c.Abort()
			return
		}

		if !valid {
			m.logger.Debug("Invalid API key")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		// Initialize metadata map
		metadata := map[string]interface{}{
			"api_key":    apiKey,
			"gateway_id": gatewayID,
		}

		// Store in context
		c.Set("api_key", apiKey)
		c.Set("metadata", metadata)

		// Set in request context for plugins
		ctx := context.WithValue(c.Request.Context(), "metadata", metadata)
		c.Request = c.Request.WithContext(ctx)

		m.logger.WithFields(logrus.Fields{
			"api_key":  apiKey,
			"metadata": metadata,
		}).Debug("API key validated and stored in context")

		c.Next()
	}
}
