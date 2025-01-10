package loadbalancer

import (
	"ai-gateway-ce/pkg/loadbalancer/strategies"
	"ai-gateway-ce/pkg/types"
	"fmt"
)

// BaseFactory implements the Factory interface with basic strategies
type BaseFactory struct{}

func NewBaseFactory() Factory {
	return &BaseFactory{}
}

func (f *BaseFactory) CreateStrategy(algorithm string, targets []types.UpstreamTarget) (Strategy, error) {
	switch algorithm {
	case "round-robin":
		return strategies.NewRoundRobin(targets), nil
	case "random":
		return strategies.NewRandom(targets), nil
	case "weighted-round-robin":
		return strategies.NewWeightedRoundRobin(targets), nil
	case "least-connections":
		return strategies.NewLeastConnections(targets), nil
	default:
		return nil, fmt.Errorf("unsupported load balancing algorithm: %s", algorithm)
	}
}
