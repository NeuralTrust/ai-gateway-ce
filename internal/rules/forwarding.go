package rules

import (
	"fmt"
	"net/url"
	"strings"
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
}

type PluginConfig struct {
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Stage    string                 `json:"stage"`    // pre_request, post_request, pre_response, post_response
	Priority int                    `json:"priority"` // Lower numbers run first
	Parallel bool                   `json:"parallel"` // Can run in parallel with other plugins
	Settings map[string]interface{} `json:"settings"`
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

func (r *CreateRequest) Validate() error {
	// Validate path
	if !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path must start with /")
	}

	// Validate target URL
	targetURL, err := url.Parse(r.Target)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if !targetURL.IsAbs() {
		return fmt.Errorf("target must be an absolute URL")
	}

	// Validate methods
	if len(r.Methods) > 0 {
		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "DELETE": true,
			"PATCH": true, "HEAD": true, "OPTIONS": true,
		}
		for _, method := range r.Methods {
			if !validMethods[strings.ToUpper(method)] {
				return fmt.Errorf("invalid HTTP method: %s", method)
			}
		}
	}

	// Validate retry attempts
	if r.RetryAttempts != nil && *r.RetryAttempts < 0 {
		return fmt.Errorf("retry attempts must be non-negative")
	}

	return nil
}

func (r *UpdateRequest) Validate() error {
	if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path must start with /")
	}

	if r.Target != "" {
		targetURL, err := url.Parse(r.Target)
		if err != nil {
			return fmt.Errorf("invalid target URL: %w", err)
		}
		if !targetURL.IsAbs() {
			return fmt.Errorf("target must be an absolute URL")
		}
	}

	if len(r.Methods) > 0 {
		validMethods := map[string]bool{
			"GET": true, "POST": true, "PUT": true, "DELETE": true,
			"PATCH": true, "HEAD": true, "OPTIONS": true,
		}
		for _, method := range r.Methods {
			if !validMethods[strings.ToUpper(method)] {
				return fmt.Errorf("invalid HTTP method: %s", method)
			}
		}
	}

	if r.RetryAttempts != nil && *r.RetryAttempts < 0 {
		return fmt.Errorf("retry attempts must be non-negative")
	}

	return nil
}
