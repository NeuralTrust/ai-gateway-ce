package rules

import (
	"time"
)

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

type CreateRequest struct {
	Path          string            `json:"path" binding:"required"`
	Target        string            `json:"target" binding:"required"`
	Methods       []string          `json:"methods,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	StripPath     *bool             `json:"strip_path,omitempty"`
	PreserveHost  *bool             `json:"preserve_host,omitempty"`
	RetryAttempts *int              `json:"retry_attempts,omitempty"`
	PluginChain   []PluginConfig    `json:"plugin_chain,omitempty"`
}

type UpdateRequest struct {
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
