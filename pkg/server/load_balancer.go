package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/models"
	"ai-gateway-ce/pkg/types"
)

const (
	defaultHealthCheckInterval = 10 * time.Second
	defaultHealthCheckTimeout  = 5 * time.Second
	defaultHealthyThreshold    = 2
	defaultUnhealthyThreshold  = 3
)

type LoadBalancer struct {
	algorithm  string
	targets    []*types.UpstreamTarget
	mu         sync.RWMutex
	logger     logrus.FieldLogger
	cache      *cache.Cache
	upstreamID string
	current    uint64
	upstream   *models.Upstream
}

func NewLoadBalancer(upstream *models.Upstream, logger logrus.FieldLogger, cache *cache.Cache) *LoadBalancer {
	targets := make([]*types.UpstreamTarget, len(upstream.Targets))
	for i, t := range upstream.Targets {
		var creds types.Credentials
		if credBytes, err := json.Marshal(t.Credentials); err == nil {
			json.Unmarshal(credBytes, &creds)
		}

		targets[i] = &types.UpstreamTarget{
			ID:          t.ID,
			Weight:      t.Weight,
			Host:        t.Host,
			Port:        t.Port,
			Protocol:    t.Protocol,
			Provider:    t.Provider,
			Models:      t.Models,
			Credentials: creds,
			Headers:     t.Headers,
			Path:        t.Path,
			Health:      &types.HealthStatus{Healthy: true},
		}
	}

	return &LoadBalancer{
		algorithm:  upstream.Algorithm,
		targets:    targets,
		logger:     logger,
		cache:      cache,
		upstreamID: upstream.ID,
		upstream:   upstream,
	}
}

func (lb *LoadBalancer) NextTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// Group targets by priority
	priorityGroups := make(map[int][]*types.UpstreamTarget)
	var priorities []int
	for _, target := range lb.targets {
		if _, exists := priorityGroups[target.Priority]; !exists {
			priorities = append(priorities, target.Priority)
		}
		priorityGroups[target.Priority] = append(priorityGroups[target.Priority], target)
	}

	// Sort priorities (ascending order - lower number = higher priority)
	sort.Ints(priorities)

	// Try each priority group until we find a healthy target
	for _, priority := range priorities {
		healthyTargets := lb.getHealthyTargets(priorityGroups[priority])
		if len(healthyTargets) > 0 {
			switch lb.algorithm {
			case "round-robin":
				return lb.roundRobin(healthyTargets)
			case "weighted-round-robin":
				return lb.weightedRoundRobin(healthyTargets)
			case "least-conn":
				return lb.leastConnections(healthyTargets)
			default:
				return lb.roundRobin(healthyTargets)
			}
		}
	}

	return nil, fmt.Errorf("no healthy targets available at any priority level")
}

func (lb *LoadBalancer) getHealthyTargets(targets []*types.UpstreamTarget) []*types.UpstreamTarget {
	healthy := make([]*types.UpstreamTarget, 0)
	for _, target := range targets {
		key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
		if val, err := lb.cache.Get(context.Background(), key); err == nil {
			var status types.HealthStatus
			if err := json.Unmarshal([]byte(val), &status); err == nil && status.Healthy {
				healthy = append(healthy, target)
			}
		} else {
			// If no health status found, consider target healthy by default
			healthy = append(healthy, target)
		}
	}
	return healthy
}

func (lb *LoadBalancer) roundRobin(targets []*types.UpstreamTarget) (*types.UpstreamTarget, error) {
	// Use Redis to maintain distributed counter
	counterKey := fmt.Sprintf("lb:counter:%s", lb.upstreamID)
	count, err := lb.cache.Client().Incr(context.Background(), counterKey).Result()
	if err != nil {
		return nil, err
	}

	// Reset counter if it exceeds target count to prevent overflow
	if count > int64(len(targets)*1000) {
		lb.cache.Client().Set(context.Background(), counterKey, 0, 0)
	}

	return targets[count%int64(len(targets))], nil
}

func (lb *LoadBalancer) weightedRoundRobin(targets []*types.UpstreamTarget) (*types.UpstreamTarget, error) {
	totalWeight := 0
	for _, target := range targets {
		totalWeight += target.Weight
	}

	if totalWeight == 0 {
		return lb.roundRobin(targets)
	}

	next := atomic.AddUint64(&lb.current, 1) % uint64(totalWeight)
	runningTotal := 0

	for _, target := range targets {
		runningTotal += target.Weight
		if uint64(runningTotal) > next {
			return target, nil
		}
	}

	return targets[0], nil
}

func (lb *LoadBalancer) leastConnections(targets []*types.UpstreamTarget) (*types.UpstreamTarget, error) {
	var selected *types.UpstreamTarget
	minConn := int32(^uint32(0) >> 1) // Max int32

	for _, target := range targets {
		conn, err := lb.getConnectionCount(target.ID)
		if err != nil {
			lb.logger.WithError(err).Error("Failed to get connection count")
			continue
		}
		if conn < minConn {
			minConn = conn
			selected = target
		}
	}

	if selected == nil {
		return lb.roundRobin(targets)
	}
	return selected, nil
}

func (lb *LoadBalancer) getConnectionCount(targetID string) (int32, error) {
	key := fmt.Sprintf("lb:conn:%s:%s", lb.upstreamID, targetID)
	count, err := lb.cache.Get(context.Background(), key)
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	val, _ := strconv.ParseInt(count, 10, 32)
	return int32(val), nil
}

func (lb *LoadBalancer) IncrementConnections(target *types.UpstreamTarget) error {
	key := fmt.Sprintf("lb:conn:%s:%s", lb.upstreamID, target.ID)
	return lb.cache.Client().Incr(context.Background(), key).Err()
}

func (lb *LoadBalancer) DecrementConnections(target *types.UpstreamTarget) error {
	key := fmt.Sprintf("lb:conn:%s:%s", lb.upstreamID, target.ID)
	return lb.cache.Client().Decr(context.Background(), key).Err()
}

func (lb *LoadBalancer) UpdateTargetHealth(target *types.UpstreamTarget, healthy bool, err error) {
	if lb.upstream.HealthChecks == nil || !lb.upstream.HealthChecks.Passive {
		return // Skip if passive health checks are not enabled
	}

	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
	failuresKey := fmt.Sprintf("lb:health:%s:%s:failures", lb.upstreamID, target.ID)

	if !healthy {
		// Increment failures counter
		failures, _ := lb.cache.Client().Incr(context.Background(), failuresKey).Result()

		// Set expiration for failures counter based on interval
		if lb.upstream.HealthChecks.Interval > 0 {
			lb.cache.Client().Expire(context.Background(), failuresKey,
				time.Duration(lb.upstream.HealthChecks.Interval)*time.Second)
		}

		// Check if failures exceed threshold
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
		// Reset failures on successful request
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

// Add this method to report failures from the proxy server
func (lb *LoadBalancer) ReportFailure(target *types.UpstreamTarget, err error) {
	lb.UpdateTargetHealth(target, false, err)
}

// Add this method to report successes from the proxy server
func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTarget) {
	lb.UpdateTargetHealth(target, true, nil)
}
