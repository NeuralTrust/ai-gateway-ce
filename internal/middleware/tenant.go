package middleware

import (
	"ai-gateway/internal/cache"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type TenantMiddleware struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	baseDomain string
}

func NewTenantMiddleware(logger *logrus.Logger, cache *cache.Cache, baseDomain string) *TenantMiddleware {
	return &TenantMiddleware{
		logger:     logger,
		cache:      cache,
		baseDomain: baseDomain,
	}
}

func (m *TenantMiddleware) IdentifyTenant() gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.Request.Host
		subdomain := m.extractSubdomain(host)

		if subdomain == "" {
			m.logger.WithField("host", host).Error("Failed to extract subdomain")
			c.JSON(400, gin.H{"error": "Invalid tenant identifier"})
			c.Abort()
			return
		}

		// Get tenant ID from subdomain mapping
		key := fmt.Sprintf("subdomain:%s", subdomain)
		tenantID, err := m.cache.Get(c, key)
		if err != nil {
			m.logger.WithError(err).Error("Failed to get tenant ID")
			c.JSON(400, gin.H{"error": "Invalid tenant identifier"})
			c.Abort()
			return
		}

		c.Set(TenantContextKey, tenantID)
		c.Next()
	}
}

func (m *TenantMiddleware) extractSubdomain(host string) string {
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	if !strings.HasSuffix(host, m.baseDomain) {
		return ""
	}

	subdomain := strings.TrimSuffix(host, "."+m.baseDomain)
	if subdomain == "" {
		return ""
	}

	return subdomain
}
