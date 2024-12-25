package types

import "context"

// RulesCacher defines the interface for caching rules
type RulesCacher interface {
	UpdateRulesCache(ctx context.Context, gatewayID string, rules []ForwardingRule) error
}
