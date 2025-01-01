package server

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
)

type LoadBalancer interface {
	SelectTarget(rule *types.ForwardingRule) (*types.Target, error)
}

type DefaultLoadBalancer struct {
	cache   *cache.Cache
	logger  *logrus.Logger
	counter uint64
}

func NewLoadBalancer(cache *cache.Cache, logger *logrus.Logger) *DefaultLoadBalancer {
	return &DefaultLoadBalancer{
		cache:  cache,
		logger: logger,
	}
}

func (lb *DefaultLoadBalancer) SelectTarget(rule *types.ForwardingRule) (*types.Target, error) {
	if len(rule.Targets) == 0 {
		return nil, fmt.Errorf("no targets available")
	}

	lb.logger.WithFields(logrus.Fields{
		"ruleID":     rule.ID,
		"strategy":   rule.LoadBalancingStrategy,
		"numTargets": len(rule.Targets),
		"targets":    rule.Targets,
	}).Debug("Selecting target")

	switch rule.LoadBalancingStrategy {
	case "weighted":
		return lb.selectWeightedTarget(rule)
	default:
		return lb.selectRoundRobinTarget(rule)
	}
}

func (lb *DefaultLoadBalancer) selectRoundRobinTarget(rule *types.ForwardingRule) (*types.Target, error) {
	key := fmt.Sprintf("lb:rr:%s", rule.ID)

	// Try Redis first
	count, err := lb.cache.Client().Incr(context.Background(), key).Result()
	if err != nil {
		// Fallback to local counter if Redis fails
		count = int64(atomic.AddUint64(&lb.counter, 1))
	}

	// Set expiration for Redis key
	lb.cache.Client().Expire(context.Background(), key, 24*time.Hour)

	index := (count - 1) % int64(len(rule.Targets))
	return &rule.Targets[index], nil
}

func (lb *DefaultLoadBalancer) selectWeightedTarget(rule *types.ForwardingRule) (*types.Target, error) {
	// Validate total weight equals 100
	totalWeight := 0
	for _, target := range rule.Targets {
		totalWeight += target.Weight
	}
	if totalWeight != 100 {
		lb.logger.WithFields(logrus.Fields{
			"ruleID":      rule.ID,
			"totalWeight": totalWeight,
		}).Warn("Invalid total weight, falling back to round-robin")
		return lb.selectRoundRobinTarget(rule)
	}

	key := fmt.Sprintf("lb:w:%s", rule.ID)

	// Get current position in weight distribution
	count, err := lb.cache.Client().Incr(context.Background(), key).Result()
	if err != nil {
		// Fallback to local counter if Redis fails
		count = int64(atomic.AddUint64(&lb.counter, 1))
	}

	// Set expiration for Redis key
	lb.cache.Client().Expire(context.Background(), key, 24*time.Hour)

	// Calculate position in weight space (0-99)
	position := (count - 1) % 100

	// Log request details
	lb.logger.WithFields(logrus.Fields{
		"ruleID":   rule.ID,
		"count":    count,
		"position": position,
	}).Debug("Processing weighted request")

	// Find target based on weight distribution
	accumulated := 0
	for _, target := range rule.Targets {
		accumulated += target.Weight
		if int64(position) < int64(accumulated) {
			lb.logger.WithFields(logrus.Fields{
				"ruleID":      rule.ID,
				"target":      target.URL,
				"weight":      target.Weight,
				"position":    position,
				"count":       count,
				"accumulated": accumulated,
			}).Debug("Selected weighted target")
			return &target, nil
		}
	}

	// If no target found (shouldn't happen with proper weights)
	lb.logger.WithFields(logrus.Fields{
		"ruleID":      rule.ID,
		"position":    position,
		"weights":     rule.Targets,
		"totalWeight": accumulated,
	}).Warn("No target found for position, using last target")
	return &rule.Targets[len(rule.Targets)-1], nil
}
