package plugins

import (
	"ai-gateway/internal/types"
	"context"
)

type Plugin interface {
	Name() string
	Priority() int
	Stage() types.ExecutionStage
	Parallel() bool
	ProcessRequest(ctx context.Context, reqCtx *types.RequestContext) error
	ProcessResponse(ctx context.Context, respCtx *types.ResponseContext) error
}

type PluginFactory interface {
	CreatePlugin(name string, config map[string]interface{}) (Plugin, error)
}

type PluginRegistry interface {
	GetPlugin(name string) (Plugin, bool)
	RegisterPlugin(name string, plugin Plugin) error
}

type PluginManager struct {
	Manager
}
