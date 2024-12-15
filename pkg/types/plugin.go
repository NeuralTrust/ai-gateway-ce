package types

import (
	"context"
	"net/url"
)

// Stage represents when a plugin should be executed
type Stage string

const (
	PreRequest   Stage = "pre_request"
	PostRequest  Stage = "post_request"
	PreResponse  Stage = "pre_response"
	PostResponse Stage = "post_response"
)

// Level represents at which level the plugin is configured
type Level string

const (
	GatewayLevel Level = "gateway"
	RuleLevel    Level = "rule"
)

// Plugin types
const (
	RateLimiterPlugin = "rate_limiter"
	// Add other plugin types here
)

// Plugin defines the interface that all plugins must implement
type Plugin interface {
	// Name returns the unique identifier of the plugin
	Name() string

	// Stages returns the stages where this plugin should be executed
	Stages() []Stage

	// Execute runs the plugin logic
	Execute(ctx context.Context, cfg PluginConfig, req *RequestContext, resp *ResponseContext) (*PluginResponse, error)
}

// PluginConfig represents the configuration for a plugin
type PluginConfig struct {
	ID       string                 `json:"id"` // ID of the gateway or rule this plugin belongs to
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Level    Level                  `json:"level"`
	Stage    Stage                  `json:"stage"`
	Priority int                    `json:"priority"`
	Parallel bool                   `json:"parallel"` // Whether this plugin can run in parallel
	Settings map[string]interface{} `json:"settings"`
}

type PluginError struct {
	StatusCode int
	Message    string
	Err        error
}

type PluginResponse struct {
	StatusCode int
	Message    string
	Body       map[string]interface{}
}

func (e *PluginError) Error() string {
	return e.Message
}

// PluginChain represents a sequence of plugins to be executed
type PluginChain struct {
	Stage    Stage          `json:"stage"`
	Parallel bool           `json:"parallel"`
	Plugins  []PluginConfig `json:"plugins"`
}

// RequestContext represents the context for a request
type RequestContext struct {
	Context   context.Context
	GatewayID string
	Headers   map[string][]string
	Method    string
	Path      string
	Query     url.Values
	Body      []byte
	Metadata  map[string]interface{}
}

// ResponseContext represents the context for a response
type ResponseContext struct {
	Context    context.Context
	GatewayID  string
	Headers    map[string][]string
	Body       []byte
	StatusCode int
	Metadata   map[string]interface{}
}

// RateLimiterConfig represents the configuration for rate limiting
type RateLimiterConfig struct {
	Limits  map[string]RateLimit `json:"limits"`
	Actions RateLimiterActions   `json:"actions"`
}

type RateLimit struct {
	Limit  int    `json:"limit"`
	Window string `json:"window"`
}

type RateLimiterActions struct {
	Type       string `json:"type"`
	RetryAfter string `json:"retry_after"`
}

type ForwardingTarget struct {
	URL    string `json:"url"`
	Weight int    `json:"weight,omitempty"` // percentage of traffic (0-100)
}

var (
	pluginRegistry = make(map[string]Plugin)
)

// RegisterPlugin registers a plugin with the registry
func RegisterPlugin(name string, plugin Plugin) {
	pluginRegistry[name] = plugin
}

// GetPlugin returns a plugin from the registry
func GetPlugin(name string) (Plugin, bool) {
	plugin, ok := pluginRegistry[name]
	return plugin, ok
}
