package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync"
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

		targets[i] = &types.UpstreamTarget{
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
		// Check target health before grouping
		health, err := lb.getTargetHealth(ctx, target.ID)
		if err == nil && health.Healthy {
			if _, exists := priorityGroups[target.Priority]; !exists {
				priorities = append(priorities, target.Priority)
			}
			priorityGroups[target.Priority] = append(priorityGroups[target.Priority], target)
		}
	}

	if len(priorities) == 0 {
		// If no healthy targets found, try to reset health status and retry
		lb.resetHealthStatus(ctx)
		return lb.fallbackTarget(ctx)
	}

	// Sort priorities (ascending order - lower number = higher priority)
	sort.Ints(priorities)

	// Try each priority group
	for _, priority := range priorities {
		targets := priorityGroups[priority]
		if len(targets) > 0 {
			switch lb.algorithm {
			case "round-robin":
				return lb.roundRobin(targets)
			case "weighted-round-robin":
				return lb.weightedRoundRobin(targets)
			case "least-conn":
				return lb.leastConnections(targets)
			default:
				return lb.roundRobin(targets)
			}
		}
	}

	return nil, fmt.Errorf("no healthy targets available")
}

func (lb *LoadBalancer) getHealthyTargets(targets []*types.UpstreamTarget) []*types.UpstreamTarget {
	healthy := make([]*types.UpstreamTarget, 0)
	for _, target := range targets {
		key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, target.ID)
		val, err := lb.cache.Get(context.Background(), key)

		// Log health check status
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
			"key":       key,
			"err":       err,
			"value":     val,
		}).Debug("Checking target health")

		if err == nil {
			var status types.HealthStatus
			if err := json.Unmarshal([]byte(val), &status); err == nil {
				target.Health = &status // Update target's health status
				if status.Healthy {
					healthy = append(healthy, target)
				}
				continue
			}
		}

		// If no health status found or error, initialize as healthy
		status := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
		}
		statusJSON, _ := json.Marshal(status)
		lb.cache.Set(context.Background(), key, string(statusJSON), time.Hour)
		target.Health = status
		healthy = append(healthy, target)
	}

	lb.logger.WithFields(logrus.Fields{
		"total_targets":   len(targets),
		"healthy_targets": len(healthy),
	}).Debug("Health check summary")

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
	// Log available targets first
	for i, target := range targets {
		lb.logger.WithFields(logrus.Fields{
			"index":    i,
			"provider": target.Provider,
			"weight":   target.Weight,
			"path":     target.Path,
		}).Debug("Available target")
	}

	totalWeight := 0
	for _, target := range targets {
		totalWeight += target.Weight
	}

	if totalWeight == 0 {
		lb.logger.Warn("Total weight is 0, falling back to round robin")
		return lb.roundRobin(targets)
	}

	// Use Redis to maintain distributed counter
	counterKey := fmt.Sprintf("lb:wrr_counter:%s", lb.upstreamID)
	count, err := lb.cache.Client().Incr(context.Background(), counterKey).Result()
	if err != nil {
		return nil, err
	}

	// Reset counter if it exceeds a large number to prevent overflow
	if count > int64(totalWeight*1000) {
		lb.cache.Client().Set(context.Background(), counterKey, 0, 0)
		count = 0
	}

	// Calculate the target based on weights
	point := count % int64(totalWeight)

	lb.logger.WithFields(logrus.Fields{
		"count":         count,
		"point":         point,
		"total_weight":  totalWeight,
		"targets_count": len(targets),
	}).Debug("Weighted round robin")

	// Select target based on weight ranges
	currentWeight := int64(0)
	for i, target := range targets {
		prevWeight := currentWeight
		currentWeight += int64(target.Weight)
		if point >= prevWeight && point < currentWeight {
			lb.logger.WithFields(logrus.Fields{
				"selected_target": i,
				"provider":        target.Provider,
				"weight_range":    fmt.Sprintf("%d-%d", prevWeight, currentWeight-1),
				"point":           point,
				"path":            target.Path,
			}).Debug("Selected target")
			return target, nil
		}
	}

	// Fallback to first target if something went wrong
	lb.logger.Warn("Falling back to first target in weighted round robin")
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
	lb.logger.WithFields(logrus.Fields{
		"target": target,
		"error":  err,
	}).Error("ReportFailure")
	lb.UpdateTargetHealth(target, false, err)
}

// Add this method to report successes from the proxy server
func (lb *LoadBalancer) ReportSuccess(target *types.UpstreamTarget) {
	lb.UpdateTargetHealth(target, true, nil)
}

// Add new method for fallback logic
func (lb *LoadBalancer) fallbackTarget(ctx context.Context) (*types.UpstreamTarget, error) {
	// Try to find any target, even if marked unhealthy
	for _, target := range lb.targets {
		lb.logger.WithFields(logrus.Fields{
			"target_id": target.ID,
			"provider":  target.Provider,
		}).Info("Attempting fallback to potentially unhealthy target")
		return target, nil
	}
	return nil, fmt.Errorf("no targets available for fallback")
}

// Add method to reset health status
func (lb *LoadBalancer) resetHealthStatus(ctx context.Context) {
	lb.logger.Info("Resetting health status for all targets")
	for _, target := range lb.targets {
		health := &types.HealthStatus{
			Healthy:   true,
			LastCheck: time.Now(),
			Failures:  0,
			LastError: nil,
		}
		lb.setTargetHealth(ctx, target.ID, health)
	}
}

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

func (lb *LoadBalancer) setTargetHealth(ctx context.Context, targetID string, health *types.HealthStatus) {
	key := fmt.Sprintf("lb:health:%s:%s", lb.upstreamID, targetID)
	healthJSON, err := json.Marshal(health)
	if err != nil {
		lb.logger.WithError(err).Error("Failed to marshal health status")
		return
	}

	lb.cache.Set(ctx, key, string(healthJSON), time.Hour)
}
