package types

import "context"

// ExecutionStage defines when a plugin should be executed
type ExecutionStage int

const (
	PreRequest ExecutionStage = iota
	PostRequest
)

// Plugin interface defines the methods that all plugins must implement
type Plugin interface {
	Name() string
	Priority() int
	Stage() ExecutionStage
	Parallel() bool
	ProcessRequest(ctx *RequestContext, pluginCtx *PluginContext) error
	ProcessResponse(ctx *ResponseContext, pluginCtx *PluginContext) error
}

// BasePlugin provides common functionality for all plugins
type BasePlugin struct{}

// RequestContext holds the context for processing requests
type RequestContext struct {
	context.Context
	Headers map[string]string
	Body    []byte
}

// ResponseContext holds the context for processing responses
type ResponseContext struct {
	context.Context
	Headers    map[string]string
	Body       []byte
	StatusCode int
	Metadata   map[string]interface{}
}

// PluginContext holds shared context between plugins
type PluginContext struct {
	Data map[string]interface{}
}
