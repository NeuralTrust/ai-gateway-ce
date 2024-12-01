package middleware

import (
	"github.com/gin-gonic/gin"
	"ai-gateway/pkg/utils"
)

const TenantContextKey = "tenant_id"

func TenantIdentification(baseDomain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		host := c.Request.Host
		tenantID := utils.ExtractTenantFromSubdomain(host, baseDomain)

		if tenantID == "" {
			c.JSON(400, gin.H{"error": "Invalid tenant identifier"})
			c.Abort()
			return
		}

		// Store tenant ID in context for downstream handlers
		c.Set(TenantContextKey, tenantID)
		c.Next()
	}
} 