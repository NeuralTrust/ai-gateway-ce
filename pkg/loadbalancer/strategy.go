package loadbalancer

import "ai-gateway-ce/pkg/types"

// Strategy defines the interface for load balancing algorithms
type Strategy interface {
	// Next returns the next target based on the algorithm
	Next() *types.UpstreamTarget
	// Name returns the name of the strategy
	Name() string
}

// Factory creates load balancing strategies
type Factory interface {
	// CreateStrategy creates a new load balancing strategy
	CreateStrategy(algorithm string, targets []types.UpstreamTarget) (Strategy, error)
}