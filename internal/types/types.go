package types

import (
	"context"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

// ExecutionStage represents the stage at which a plugin is executed
type ExecutionStage string

const (
	PreRequest   ExecutionStage = "pre_request"
	PostRequest  ExecutionStage = "post_request"
	PreResponse  ExecutionStage = "pre_response"
	PostResponse ExecutionStage = "post_response"
)

// RequestContext represents the context for processing requests
type RequestContext struct {
	GatewayID          string                 `json:"gateway_id"`
	Path               string                 `json:"path"`
	Method             string                 `json:"method"`
	Headers            map[string]string      `json:"headers"`
	Body               []byte                 `json:"body"`
	Context            context.Context        `json:"context"`
	Request            *fasthttp.Request      `json:"request"`
	Response           *fasthttp.Response     `json:"response"`
	Modified           bool                   `json:"modified"`
	Metadata           map[string]interface{} `json:"metadata"`
	ValidationResponse []byte                 `json:"validation_response"`
	OriginalRequest    *fasthttp.Request      `json:"original_request"`
	ForwardRequest     *fasthttp.Request      `json:"forward_request"`
	StopForwarding     bool                   `json:"stop_forwarding"`
}

// ResponseContext represents the context for processing responses
type ResponseContext struct {
	GatewayID        string                 `json:"gateway_id"`
	Headers          map[string]string      `json:"headers"`
	Body             []byte                 `json:"body"`
	Context          context.Context        `json:"context"`
	Request          *fasthttp.Request      `json:"request"`
	Response         *fasthttp.Response     `json:"response"`
	Modified         bool                   `json:"modified"`
	Metadata         map[string]interface{} `json:"metadata"`
	OriginalRequest  *fasthttp.Request      `json:"original_request"`
	OriginalResponse *fasthttp.Response     `json:"original_response"`
}

// PluginError represents a plugin execution error
type PluginError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

func (e *PluginError) Error() string {
	return e.Message
}

// ResponseCondition represents a condition for response validation
type ResponseCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	StopFlow bool        `json:"stop_flow"`
	Message  string      `json:"message"`
}

// PluginConfig represents the configuration for a plugin
type PluginConfig struct {
	Name       string                 `json:"name"`
	Enabled    bool                   `json:"enabled"`
	Priority   int                    `json:"priority"`
	Stage      string                 `json:"stage"`
	Parallel   bool                   `json:"parallel"`
	Settings   map[string]interface{} `json:"settings"`
	Conditions []ResponseCondition    `json:"conditions,omitempty"`
}

// Request/Response types for API
type CreateGatewayRequest struct {
	Name            string                  `json:"name" binding:"required"`
	Subdomain       string                  `json:"subdomain" binding:"required"`
	Tier            string                  `json:"tier" binding:"required"`
	EnabledPlugins  []string                `json:"enabled_plugins"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins"`
}

type UpdateGatewayRequest struct {
	Name            *string                 `json:"name,omitempty"`
	Status          *string                 `json:"status,omitempty"`
	Tier            *string                 `json:"tier,omitempty"`
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
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
}

type UpdateRuleRequest struct {
	Path          string            `json:"path"`
	Target        string            `json:"target"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     *bool             `json:"strip_path"`
	PreserveHost  *bool             `json:"preserve_host"`
	RetryAttempts *int              `json:"retry_attempts"`
	Active        *bool             `json:"active"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
}

// Gateway represents a tenant's gateway configuration
type Gateway struct {
	ID              string                  `json:"id"`
	Name            string                  `json:"name"`
	Subdomain       string                  `json:"subdomain"`
	ApiKey          string                  `json:"api_key"`
	Status          string                  `json:"status"`
	Tier            string                  `json:"tier"`
	EnabledPlugins  []string                `json:"enabled_plugins"`
	RequiredPlugins map[string]PluginConfig `json:"required_plugins"`
	CreatedAt       string                  `json:"created_at"`
	UpdatedAt       string                  `json:"updated_at"`
}

// APIKey represents an API key for gateway authentication
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Key        string     `json:"key"`
	GatewayID  string     `json:"gateway_id"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Status     string     `json:"status"`
}

// ForwardingRule represents a rule for forwarding requests
type ForwardingRule struct {
	ID            string            `json:"id"`
	GatewayID     string            `json:"gateway_id"`
	Path          string            `json:"path"`
	Target        string            `json:"target"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     bool              `json:"strip_path"`
	PreserveHost  bool              `json:"preserve_host"`
	RetryAttempts int               `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
	Active        bool              `json:"active"`
	Public        bool              `json:"public"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

// EvaluateCondition evaluates a response condition against a value
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

// Helper functions for condition evaluation
func compareNumbers(a, b interface{}) int {
	var aFloat, bFloat float64

	switch v := a.(type) {
	case int:
		aFloat = float64(v)
	case int32:
		aFloat = float64(v)
	case int64:
		aFloat = float64(v)
	case float32:
		aFloat = float64(v)
	case float64:
		aFloat = v
	default:
		return 0
	}

	switch v := b.(type) {
	case int:
		bFloat = float64(v)
	case int32:
		bFloat = float64(v)
	case int64:
		bFloat = float64(v)
	case float32:
		bFloat = float64(v)
	case float64:
		bFloat = v
	default:
		return 0
	}

	if aFloat < bFloat {
		return -1
	}
	if aFloat > bFloat {
		return 1
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
	case map[string]interface{}:
		for _, item := range v {
			if item == searchValue {
				return true
			}
		}
	}
	return false
}

// Add PluginContext type
type PluginContext struct {
	Config   PluginConfig
	Redis    *redis.Client
	Logger   *logrus.Logger
	Metadata map[string]interface{}
}

// Plugin interface defines the methods that all plugins must implement
type Plugin interface {
	Name() string
	Priority() int
	Stage() ExecutionStage
	Parallel() bool
	ProcessRequest(reqCtx *RequestContext, pluginCtx *PluginContext) error
	ProcessResponse(respCtx *ResponseContext, pluginCtx *PluginContext) error
	Configure(config PluginConfig) error
}
