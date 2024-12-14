package middleware

import (
	"ai-gateway-ce/pkg/cache"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type GatewayMiddleware struct {
	logger     *logrus.Logger
	cache      *cache.Cache
	baseDomain string
}

func NewGatewayMiddleware(logger *logrus.Logger, cache *cache.Cache, baseDomain string) *GatewayMiddleware {
	return &GatewayMiddleware{
		logger:     logger,
		cache:      cache,
		baseDomain: baseDomain,
	}
}

func (m *GatewayMiddleware) IdentifyGateway() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to get host from different sources
		host := c.GetHeader("Host")
		if host == "" {
			host = c.Request.Host
		}

		m.logger.WithFields(logrus.Fields{
			"host":       host,
			"baseDomain": m.baseDomain,
			"path":       c.Request.URL.Path,
			"method":     c.Request.Method,
			"headers":    c.Request.Header,
		}).Debug("Processing request")

		// Skip middleware for system endpoints
		if strings.HasPrefix(c.Request.URL.Path, "/__/") {
			c.Next()
			return
		}

		subdomain := m.extractSubdomain(host)
		if subdomain == "" {
			m.logger.WithFields(logrus.Fields{
				"host":       host,
				"baseDomain": m.baseDomain,
				"headers":    c.Request.Header,
			}).Error("Failed to extract subdomain")
			c.JSON(400, gin.H{"error": "Invalid gateway identifier"})
			c.Abort()
			return
		}

		m.logger.WithFields(logrus.Fields{
			"host":      host,
			"subdomain": subdomain,
			"path":      c.Request.URL.Path,
		}).Debug("Extracted subdomain")

		// Get gateway ID from subdomain mapping
		key := fmt.Sprintf("subdomain:%s", subdomain)
		gatewayID, err := m.cache.Get(c, key)
		if err != nil {
			if err.Error() == "redis: nil" {
				m.logger.WithFields(logrus.Fields{
					"subdomain": subdomain,
					"key":       key,
					"host":      host,
					"path":      c.Request.URL.Path,
				}).Error("Gateway not found")
				c.JSON(404, gin.H{"error": "Gateway not found"})
			} else {
				m.logger.WithFields(logrus.Fields{
					"error":     err.Error(),
					"subdomain": subdomain,
					"key":       key,
					"host":      host,
				}).Error("Failed to get gateway ID")
				c.JSON(500, gin.H{"error": "Internal server error"})
			}
			c.Abort()
			return
		}

		m.logger.WithFields(logrus.Fields{
			"subdomain": subdomain,
			"gatewayID": gatewayID,
			"host":      host,
			"path":      c.Request.URL.Path,
		}).Debug("Found gateway")

		c.Set(GatewayContextKey, gatewayID)
	}
}

func (m *GatewayMiddleware) extractSubdomain(host string) string {
	m.logger.WithFields(logrus.Fields{
		"host":       host,
		"baseDomain": m.baseDomain,
	}).Debug("Extracting subdomain")

	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
		m.logger.WithFields(logrus.Fields{
			"original": host + ":" + host[colonIndex+1:],
			"stripped": host,
		}).Debug("Removed port from host")
	}

	// Check if host ends with base domain
	suffix := "." + m.baseDomain
	if !strings.HasSuffix(host, suffix) {
		m.logger.WithFields(logrus.Fields{
			"host":       host,
			"baseDomain": m.baseDomain,
			"suffix":     suffix,
			"hasSuffix":  strings.HasSuffix(host, suffix),
			"hostLen":    len(host),
			"suffixLen":  len(suffix),
		}).Debug("Host does not match base domain")
		return ""
	}

	// Extract subdomain by removing the base domain and the dot
	subdomain := strings.TrimSuffix(host, suffix)
	if subdomain == "" {
		m.logger.WithFields(logrus.Fields{
			"host":   host,
			"suffix": suffix,
		}).Debug("No subdomain found")
		return ""
	}

	m.logger.WithFields(logrus.Fields{
		"host":      host,
		"subdomain": subdomain,
		"suffix":    suffix,
	}).Debug("Successfully extracted subdomain")

	return subdomain
}
