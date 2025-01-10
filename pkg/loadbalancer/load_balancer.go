package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
)

const (
	defaultHealthCheckInterval = 10 * time.Second
	defaultHealthCheckTimeout  = 5 * time.Second
	defaultHealthyThreshold    = 2
	defaultUnhealthyThreshold  = 3
)

type LoadBalancer struct {
	mu         sync.RWMutex
	strategy   Strategy
	logger     *logrus.Logger
	cache      *cache.Cache
	upstreamID string
	upstream   *models.Upstream
}

func NewLoadBalancer(upstream *models.Upstream, logger *logrus.Logger, cache *cache.Cache) (*LoadBalancer, error) {
	// Convert upstream targets to UpstreamTarget type
	targets := make([]types.UpstreamTarget, len(upstream.Targets))
	for i, t := range upstream.Targets {
		var creds types.Credentials
		if credBytes, err := json.Marshal(t.Credentials); err == nil {
			json.Unmarshal(credBytes, &creds)
		}

		// Initialize health status
		healthStatus := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
		}

		// Store initial health status in cache
		key := fmt.Sprintf("lb:health:%s:%s", upstream.ID, t.ID)
		if statusJSON, err := json.Marshal(healthStatus); err == nil {
			cache.Set(context.Background(), key, string(statusJSON), time.Hour)
		}

		targets[i] = types.UpstreamTarget{
			ID:           t.ID,
			Weight:       t.Weight,
			Priority:     t.Priority,
			Host:         t.Host,
			Port:         t.Port,
			Protocol:     t.Protocol,
			Provider:     t.Provider,
			Models:       t.Models,
			DefaultModel: t.DefaultModel,
			Credentials:  creds,
			Headers:      t.Headers,
			Path:         t.Path,
			Health:       healthStatus,
		}
	}

	// Create the base factory
	factory := NewBaseFactory()

	// Create strategy based on algorithm
	strategy, err := factory.CreateStrategy(upstream.Algorithm, targets)
	if err != nil {
		return nil, fmt.Errorf("failed to create load balancing strategy: %w", err)
	}

	return &LoadBalancer{
		strategy:   strategy,
		logger:     logger,
		cache:      cache,
		upstreamID: upstream.ID,
		upstream:   upstream,
	}, nil
}

func (lb *LoadBalancer) NextTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	target := lb.strategy.Next()
	if target == nil {
		return nil, fmt.Errorf("no available targets")
	}

	// Check target health
	health, err := lb.getTargetHealth(ctx, target.ID)
	if err == nil && health.Healthy {
		return target, nil
	}

	// If target is unhealthy, try to get another one
	return lb.fallbackTarget(ctx)
}

// Add all the health check methods from the original load balancer
func (lb *LoadBalancer) UpdateTargetHealth(target *types.UpstreamTarget, healthy bool, err error) {
	if lb.upstream.HealthChecks == nil || !lb.upstream.HealthChecks.Passive {
		return
	}

	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.upstreamID, target.ID)

	if !healthy {
		failures, _ := lb.cache.Client().Incr(context.Background(), failuresKey).Result()

		if lb.upstream.HealthChecks.Interval > 0 {
			lb.cache.Client().Expire(context.Background(), failuresKey,
				time.Duration(lb.upstream.HealthChecks.Interval)*time.Second)
		}

		if failures >= int64(lb.upstream.HealthChecks.Threshold) {
			status := &types.HealthStatus{
				Healthy:   false,
				LastCheck: time.Now(),
				LastError: err,
				Failures:  int(failures),
			}
			statusJSON, _ := json.Marshal(status)
			lb.cache.Set(context.Background(), key, string(statusJSON), time.Hour)
		}
	} else {
		lb.cache.Delete(context.Background(), failuresKey)

		status := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
			LastError: nil,
			Failures:  0,
		}
		statusJSON, _ := json.Marshal(status)
		lb.cache.Set(context.Background(), key, string(statusJSON), time.Hour)
	}
}

func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTarget) {
	lb.UpdateTargetHealth(target, true, nil)
}

func (lb *LoadBalancer) ReportFailure(target *types.UpstreamTarget, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

// Add the helper methods for health checks
func (lb *LoadBalancer) getTargetHealth(ctx context.Context, targetID string) (*types.HealthStatus, error) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	val, err := lb.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var health types.HealthStatus
	if err := json.Unmarshal([]byte(val), &health); err != nil {
		return nil, err
	}

	return &health, nil
}

func (lb *LoadBalancer) fallbackTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	target := lb.strategy.Next()
	if target != nil {
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
		}).Info("Using fallback target")
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}