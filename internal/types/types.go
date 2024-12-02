package types

import (
	"time"
)

// Plugin Configuration
type PluginConfig struct {
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Stage    string                 `json:"stage"`
	Settings map[string]interface{} `json:"settings"`
}

// Tenant types
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

// API Key types
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

// Forwarding Rule types
type ForwardingRule struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	Path          string            `json:"path"`
	Target        string            `json:"target"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     bool              `json:"strip_path"`
	Active        bool              `json:"active"`
	PreserveHost  bool              `json:"preserve_host"`
	RetryAttempts int               `json:"retry_attempts,omitempty"`
	PluginChain   []PluginConfig    `json:"plugin_chain,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type CreateRuleRequest struct {
	Path          string            `json:"path" binding:"required"`
	Target        string            `json:"target" binding:"required"`
	Methods       []string          `json:"methods,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     *bool             `json:"strip_path,omitempty"`
	PreserveHost  *bool             `json:"preserve_host,omitempty"`
	RetryAttempts *int              `json:"retry_attempts,omitempty"`
	PluginChain   []PluginConfig    `json:"plugin_chain,omitempty"`
}

type UpdateRuleRequest struct {
	Path          string            `json:"path,omitempty"`
	Target        string            `json:"target,omitempty"`
	Methods       []string          `json:"methods,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     *bool             `json:"strip_path,omitempty"`
	Active        *bool             `json:"active,omitempty"`
	PreserveHost  *bool             `json:"preserve_host,omitempty"`
	RetryAttempts *int              `json:"retry_attempts,omitempty"`
	PluginChain   []PluginConfig    `json:"plugin_chain,omitempty"`
}
