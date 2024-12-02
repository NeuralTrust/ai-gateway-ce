package rules

import (
	"time"
)

type Tenant struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Subdomain       string                  `json:"subdomain"`
	ApiKey          string                  `json:"api_key"`
	Status          string                  `json:"status"`
	Tier            string                  `json:"tier"`
	CreatedAt       time.Time               `json:"created_at"`
	UpdatedAt       time.Time               `json:"updated_at"`
	EnabledPlugins  []string                `json:"enabled_plugins"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins"`
}

type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Key        string     `json:"key"`
	TenantID   string     `json:"tenant_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Status     string     `json:"status"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type CreateTenantRequest struct {
	Name            string                  `json:"name" binding:"required"`
	Subdomain       string                  `json:"subdomain" binding:"required"`
	Tier            string                  `json:"tier" binding:"required"`
	EnabledPlugins  []string                `json:"enabled_plugins"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins"`
}

type UpdateTenantRequest struct {
	Name            string                  `json:"name,omitempty"`
	Status          string                  `json:"status,omitempty"`
	Tier            string                  `json:"tier,omitempty"`
	EnabledPlugins  []string                `json:"enabled_plugins,omitempty"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins,omitempty"`
}
