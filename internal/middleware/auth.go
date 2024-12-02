package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/types"
)

type AuthMiddleware struct {
	cache  *cache.Cache
	logger *logrus.Logger
}

func NewAuthMiddleware(cache *cache.Cache, logger *logrus.Logger) *AuthMiddleware {
	return &AuthMiddleware{
		cache:  cache,
		logger: logger,
	}
}

func (m *AuthMiddleware) ValidateAPIKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip validation for tenant creation
		if c.Request.Method == "POST" && c.FullPath() == "/api/v1/tenants" {
			c.Next()
			return
		}

		// Get tenant ID from context
		tenantID, exists := c.Get(TenantContextKey)
		if !exists {
			m.logger.Error("Tenant ID not found in context")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID is required"})
			c.Abort()
			return
		}

		// Get API key from header
		authHeader := c.GetHeader(AuthHeaderKey)
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key is required"})
			c.Abort()
			return
		}

		if !strings.HasPrefix(authHeader, AuthPrefix) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key format"})
			c.Abort()
			return
		}

		apiKey := strings.TrimPrefix(authHeader, AuthPrefix)

		// Get all API keys for the tenant
		setKey := fmt.Sprintf("tenant:%s:apikeys", tenantID)
		keyIDs, err := m.cache.SMembers(c, setKey)
		if err != nil {
			m.logger.WithError(err).Error("Failed to get API keys")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate API key"})
			c.Abort()
			return
		}

		// Check each API key
		for _, keyID := range keyIDs {
			key := fmt.Sprintf("apikey:%s:%s", tenantID, keyID)
			apiKeyJSON, err := m.cache.Get(c, key)
			if err != nil {
				continue
			}

			var storedKey types.APIKey
			if err := json.Unmarshal([]byte(apiKeyJSON), &storedKey); err != nil {
				continue
			}

			// Validate key
			if storedKey.Key == apiKey {
				// Check if key is active
				if storedKey.Status != "active" {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "API key is not active"})
					c.Abort()
					return
				}

				// Check expiration
				if storedKey.ExpiresAt != nil && time.Now().After(*storedKey.ExpiresAt) {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "API key has expired"})
					c.Abort()
					return
				}

				// Update last used timestamp
				storedKey.LastUsedAt = &time.Time{}
				*storedKey.LastUsedAt = time.Now()
				updatedJSON, _ := json.Marshal(storedKey)
				m.cache.Set(c, key, string(updatedJSON), 0)

				// Key is valid
				c.Set("api_key_id", storedKey.ID)
				c.Next()
				return
			}
		}

		// Check tenant's main API key as fallback
		tenantKey := fmt.Sprintf("tenant:%s", tenantID)
		tenantJSON, err := m.cache.Get(c, tenantKey)
		if err == nil {
			var tenant types.Tenant
			if err := json.Unmarshal([]byte(tenantJSON), &tenant); err == nil {
				if tenant.ApiKey == apiKey {
					c.Next()
					return
				}
			}
		}

		m.logger.WithFields(logrus.Fields{
			"tenant_id": tenantID,
		}).Warn("Invalid API key attempt")

		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
		c.Abort()
	}
}
