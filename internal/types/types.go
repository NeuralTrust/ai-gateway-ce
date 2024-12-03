package types

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Plugin related types
type ExecutionStage string

const (
	PreRequest  ExecutionStage = "pre_request"
	PostRequest ExecutionStage = "post_request"
)

// Request/Response types for API
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

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
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
	Public        bool              `json:"public"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type RequestContext struct {
	Ctx                context.Context
	TenantID           string
	OriginalRequest    *http.Request
	ForwardRequest     *http.Request
	Rule               *ForwardingRule
	Metadata           map[string]interface{}
	ValidationResponse []byte
	StopForwarding     bool
}

type ResponseContext struct {
	Ctx              context.Context
	TenantID         string
	OriginalRequest  *http.Request
	OriginalResponse *http.Response
	Response         *http.Response
	Rule             *ForwardingRule
	Metadata         map[string]interface{}
}

type PluginConfig struct {
	Name       string                 `json:"name"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	Stage      string                 `json:"stage"`
	Parallel   bool                   `json:"parallel"`
	Settings   map[string]interface{} `json:"settings"`
	Conditions []ResponseCondition    `json:"conditions,omitempty"`
}

type ResponseCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	StopFlow bool        `json:"stop_flow"`
	Message  string      `json:"message"`
}

type PluginError struct {
	Message    string `json:"message"`
	StatusCode int    `json:"status_code"`
}

func (e *PluginError) Error() string {
	return e.Message
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

// Add these functions at the end of the file
func EvaluateCondition(condition ResponseCondition, value interface{}) bool {
	switch condition.Operator {
	case "eq":
		return value == condition.Value
	case "ne":
		return value != condition.Value
	case "gt":
		return compareNumbers(value, condition.Value) > 0
	case "gte":
		return compareNumbers(value, condition.Value) >= 0
	case "lt":
		return compareNumbers(value, condition.Value) < 0
	case "lte":
		return compareNumbers(value, condition.Value) <= 0
	case "contains":
		return containsValue(value, condition.Value)
	case "not_contains":
		return !containsValue(value, condition.Value)
	case "exists":
		return value != nil
	case "not_exists":
		return value == nil
	default:
		return false
	}
}

func compareNumbers(a, b interface{}) int {
	var aFloat, bFloat float64

	switch v := a.(type) {
	case float64:
		aFloat = v
	case float32:
		aFloat = float64(v)
	case int:
		aFloat = float64(v)
	case int64:
		aFloat = float64(v)
	default:
		return 0
	}

	switch v := b.(type) {
	case float64:
		bFloat = v
	case float32:
		bFloat = float64(v)
	case int:
		bFloat = float64(v)
	case int64:
		bFloat = float64(v)
	default:
		return 0
	}

	if aFloat > bFloat {
		return 1
	} else if aFloat < bFloat {
		return -1
	}
	return 0
}

func containsValue(value, searchValue interface{}) bool {
	switch v := value.(type) {
	case string:
		searchStr, ok := searchValue.(string)
		if !ok {
			return false
		}
		return strings.Contains(v, searchStr)
	case []interface{}:
		for _, item := range v {
			if item == searchValue {
				return true
			}
		}
	}
	return false
}
