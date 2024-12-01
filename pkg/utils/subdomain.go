package utils

import (
	"strings"
)

// ExtractTenantFromSubdomain extracts the tenant identifier from the host
// Example: tenant1.example.com -> tenant1
func ExtractTenantFromSubdomain(host string, baseDomain string) string {
	if host == "" || baseDomain == "" {
		return ""
	}

	// Remove the base domain and any port number
	host = strings.Split(host, ":")[0]
	if !strings.HasSuffix(host, baseDomain) {
		return ""
	}

	// Remove the base domain and the trailing dot
	tenant := strings.TrimSuffix(host, "."+baseDomain)
	
	// Validate tenant name contains only allowed characters
	if !isValidTenantName(tenant) {
		return ""
	}

	return tenant
}

// isValidTenantName checks if the tenant name contains only allowed characters
func isValidTenantName(tenant string) bool {
	if len(tenant) == 0 {
		return false
	}
	
	for _, char := range tenant {
		if !((char >= 'a' && char <= 'z') || 
			(char >= '0' && char <= '9') || 
			char == '-') {
			return false
		}
	}
	return true
} 