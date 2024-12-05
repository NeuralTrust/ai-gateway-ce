package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Repository struct {
	db *DB
}

func NewRepository(db *DB) *Repository {
	return &Repository{db: db}
}

// Gateway operations
func (r *Repository) CreateGateway(ctx context.Context, gateway *Gateway) error {
	query := `
		INSERT INTO gateways (
			id, name, subdomain, api_key, status, tier, 
			created_at, updated_at, enabled_plugins, required_plugins
		) VALUES (
			:id, :name, :subdomain, :api_key, :status, :tier,
			:created_at, :updated_at, :enabled_plugins, :required_plugins
		)`

	_, err := r.db.NamedExecContext(ctx, query, gateway)
	return err
}

func (r *Repository) GetGateway(ctx context.Context, id string) (*Gateway, error) {
	// Add validation before querying database
	if id == "" || id == "null" {
		return nil, fmt.Errorf("invalid gateway ID: cannot be empty or null")
	}

	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid gateway ID format: %v", err)
	}

	var gateway Gateway
	err := r.db.GetContext(ctx, &gateway, "SELECT * FROM gateways WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &gateway, nil
}

func (r *Repository) GetGatewayBySubdomain(ctx context.Context, subdomain string) (*Gateway, error) {
	query := `
		SELECT id, name, subdomain, api_key, status, tier, enabled_plugins, required_plugins,
			   created_at, updated_at
		FROM gateways
		WHERE subdomain = $1
	`

	var gateway Gateway
	err := r.db.GetContext(ctx, &gateway, query, subdomain)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &gateway, nil
}

func (r *Repository) ListGateways(ctx context.Context, offset, limit int) ([]Gateway, error) {
	var gateways []Gateway
	err := r.db.SelectContext(ctx, &gateways, "SELECT * FROM gateways ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset)
	return gateways, err
}

func (r *Repository) UpdateGateway(ctx context.Context, gateway *Gateway) error {
	query := `
		UPDATE gateways SET 
			name = :name,
			status = :status,
			tier = :tier,
			updated_at = :updated_at,
			enabled_plugins = :enabled_plugins,
			required_plugins = :required_plugins
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, gateway)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("gateway not found")
	}
	return nil
}

func (r *Repository) DeleteGateway(ctx context.Context, id string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM gateways WHERE id = $1", id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("gateway not found")
	}
	return nil
}

// Forwarding Rule operations
func (r *Repository) CreateRule(ctx context.Context, rule *ForwardingRule) error {
	query := `
		INSERT INTO forwarding_rules (
			id, gateway_id, path, target, methods, headers, strip_path, preserve_host,
			retry_attempts, plugin_chain, active, public, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`

	// Convert plugin chain to proper JSON array
	var pluginChain []byte
	if len(rule.PluginChain) > 0 {
		pluginChain = []byte(rule.PluginChain)
	} else {
		pluginChain = []byte("[]")
	}

	_, err := r.db.ExecContext(ctx, query,
		rule.ID,
		rule.GatewayID,
		rule.Path,
		rule.Target,
		rule.Methods,
		rule.Headers,
		rule.StripPath,
		rule.PreserveHost,
		rule.RetryAttempts,
		pluginChain,
		rule.Active,
		rule.Public,
		rule.CreatedAt,
		rule.UpdatedAt,
	)

	return err
}

func (r *Repository) GetRule(ctx context.Context, id string, gatewayID string) (*ForwardingRule, error) {
	query := `
		SELECT id, gateway_id, path, target, methods, headers, strip_path, preserve_host,
			   retry_attempts, plugin_chain, active, public, created_at, updated_at
		FROM forwarding_rules
		WHERE id = $1 AND gateway_id = $2
	`

	var rule ForwardingRule
	err := r.db.GetContext(ctx, &rule, query, id, gatewayID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &rule, nil
}

func (r *Repository) ListRules(ctx context.Context, gatewayID string) ([]ForwardingRule, error) {
	query := `
		SELECT id, gateway_id, path, target, methods, headers, strip_path, preserve_host,
			   retry_attempts, plugin_chain, active, public, created_at, updated_at
		FROM forwarding_rules
		WHERE gateway_id = $1
		ORDER BY created_at DESC
	`

	var rules []ForwardingRule
	err := r.db.SelectContext(ctx, &rules, query, gatewayID)
	if err != nil {
		return nil, err
	}

	return rules, nil
}

func (r *Repository) UpdateRule(ctx context.Context, rule *ForwardingRule) error {
	query := `
		UPDATE forwarding_rules
		SET path = $1, target = $2, methods = $3, headers = $4, strip_path = $5,
			preserve_host = $6, retry_attempts = $7, plugin_chain = $8, active = $9,
			public = $10, updated_at = $11
		WHERE id = $12 AND gateway_id = $13
	`

	// Convert plugin chain to proper JSON array
	var pluginChain []byte
	if len(rule.PluginChain) > 0 {
		pluginChain = []byte(rule.PluginChain)
	} else {
		pluginChain = []byte("[]")
	}

	result, err := r.db.ExecContext(ctx, query,
		rule.Path,
		rule.Target,
		rule.Methods,
		rule.Headers,
		rule.StripPath,
		rule.PreserveHost,
		rule.RetryAttempts,
		pluginChain,
		rule.Active,
		rule.Public,
		rule.UpdatedAt,
		rule.ID,
		rule.GatewayID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

func (r *Repository) DeleteRule(ctx context.Context, id string, gatewayID string) error {
	query := `DELETE FROM forwarding_rules WHERE id = $1 AND gateway_id = $2`

	result, err := r.db.ExecContext(ctx, query, id, gatewayID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// API Key operations
func (r *Repository) CreateAPIKey(ctx context.Context, apiKey *APIKey) error {
	query := `
		INSERT INTO api_keys (
			id, name, key, gateway_id, created_at,
			expires_at, last_used_at, status
		) VALUES (
			:id, :name, :key, :gateway_id, :created_at,
			:expires_at, :last_used_at, :status
		)`

	_, err := r.db.NamedExecContext(ctx, query, apiKey)
	return err
}

func (r *Repository) GetAPIKey(ctx context.Context, id string) (*APIKey, error) {
	var apiKey APIKey
	err := r.db.GetContext(ctx, &apiKey, "SELECT * FROM api_keys WHERE id = $1", id)
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

func (r *Repository) ListAPIKeys(ctx context.Context, gatewayID string) ([]APIKey, error) {
	var apiKeys []APIKey
	err := r.db.SelectContext(ctx, &apiKeys, "SELECT * FROM api_keys WHERE gateway_id = $1", gatewayID)
	return apiKeys, err
}

func (r *Repository) UpdateAPIKey(ctx context.Context, apiKey *APIKey) error {
	query := `
		UPDATE api_keys SET 
			name = :name,
			status = :status,
			expires_at = :expires_at,
			last_used_at = :last_used_at
		WHERE id = :id AND gateway_id = :gateway_id`

	result, err := r.db.NamedExecContext(ctx, query, apiKey)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("api key not found")
	}
	return nil
}

func (r *Repository) DeleteAPIKey(ctx context.Context, id, gatewayID string) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM api_keys WHERE id = $1 AND gateway_id = $2", id, gatewayID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("api key not found")
	}
	return nil
}

func (r *Repository) SubdomainExists(ctx context.Context, subdomain string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM gateways
			WHERE subdomain = $1
		)`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query, subdomain)
	if err != nil {
		return false, err
	}
	return exists, nil
}
