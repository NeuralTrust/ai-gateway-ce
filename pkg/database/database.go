package database

import (
	"ai-gateway-ce/pkg/types"
)

type Database interface {
	// Gateway operations
	SaveGateway(gateway types.Gateway) error
	ListGateways() ([]types.Gateway, error)
	GetGateway(id string) (*types.Gateway, error)
	UpdateGateway(gateway types.Gateway) error
	DeleteGateway(id string) error

	// Rule operations
	SaveRule(gatewayID string, rule types.Rule) error
	ListRules(gatewayID string) ([]types.Rule, error)
	GetRule(gatewayID, ruleID string) (*types.Rule, error)
	UpdateRule(gatewayID string, rule types.Rule) error
	DeleteRule(gatewayID, ruleID string) error
}
