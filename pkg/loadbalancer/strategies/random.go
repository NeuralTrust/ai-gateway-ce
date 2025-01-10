package strategies

import (
	"ai-gateway-ce/pkg/types"
	"math/rand/v2"
	"sync"
)

type Random struct {
	mu      sync.Mutex
	targets []types.UpstreamTarget
}

func NewRandom(targets []types.UpstreamTarget) *Random {
	return &Random{
		targets: targets,
	}
}

func (r *Random) Next() *types.UpstreamTarget {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.targets) == 0 {
		return nil
	}

	return &r.targets[rand.Intn(len(r.targets))]
}

func (r *Random) Name() string {
	return "random"
}
