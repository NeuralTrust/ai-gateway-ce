package pluginiface

import (
	"context"

	"ai-gateway-ce/pkg/types"
)

type Plugin interface {
	Name() string
	Stages() []types.Stage
	Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error)
}

type PluginValidator interface {
	ValidateConfig(config types.PluginConfig) error
}
