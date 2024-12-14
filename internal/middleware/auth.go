package middleware

import (
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
		// Extract API key from Authorization header
		authHeader := c.GetHeader("Authorization")
		var apiKey string
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		}

		// If no API key provided, return 401
		if apiKey == "" {
			m.logger.Debug("No Authorization header found")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "API key required",
			})
			return
		}

		// Validate API key against database
		gatewayID, exists := c.Get(GatewayContextKey)
		if !exists {
			m.logger.Error("Gateway ID not found in context")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
			})
			return
		}

		valid, err := m.db.ValidateAPIKey(c.Request.Context(), gatewayID.(string), apiKey)
		if err != nil {
			m.logger.WithError(err).Error("Database error during API key validation")
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": "Internal server error",
			})
			return
		}

		if !valid {
			m.logger.WithFields(logrus.Fields{
				"gateway_id": gatewayID,
				"api_key":    apiKey,
			}).Debug("Invalid API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid API key",
			})
			return
		}

		// API key is valid, do not call c.Next() here
		// Since we're calling this middleware directly, calling c.Next()
		// would cause unintended behavior
	}
}
