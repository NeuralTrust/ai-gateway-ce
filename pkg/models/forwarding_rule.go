package models

import (
	"ai-gateway-ce/pkg/types"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// CredentialsJSON implements SQL/JSON conversion for *types.Credentials
type CredentialsJSON types.Credentials

// Value implements the driver.Valuer interface
func (c *CredentialsJSON) Value() (driver.Value, error) {
	if c == nil {
		return nil, nil
	}
	return json.Marshal(c)
}

// Scan implements the sql.Scanner interface
func (c *CredentialsJSON) Scan(value interface{}) error {
	if value == nil {
		*c = CredentialsJSON{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, c)
}

// ToCredentials converts CredentialsJSON to *types.Credentials
func (c *CredentialsJSON) ToCredentials() *types.Credentials {
	if c == nil {
		return nil
	}
	creds := types.Credentials(*c)
	return &creds
}

// FromCredentials converts *types.Credentials to *CredentialsJSON
func FromCredentials(c *types.Credentials) *CredentialsJSON {
	if c == nil {
		return nil
	}
	creds := CredentialsJSON(*c)
	return &creds
}

// ForwardingRule represents a forwarding rule in the database
type ForwardingRule struct {
	ID                    string            `gorm:"primaryKey"`
	GatewayID             string            `gorm:"not null"`
	Path                  string            `gorm:"not null"`
	Targets               TargetsJSON       `gorm:"type:jsonb;not null"`
	Credentials           *CredentialsJSON  `json:"credentials" gorm:"type:jsonb"`
	FallbackTargets       TargetsJSON       `json:"fallback_targets" gorm:"type:jsonb"`
	FallbackProvider      string            `json:"fallback_provider,omitempty"`
	FallbackCredentials   *CredentialsJSON  `json:"fallback_credentials" gorm:"type:jsonb"`
	Methods               MethodsJSON       `gorm:"type:jsonb"`
	Headers               map[string]string `gorm:"type:jsonb"`
	StripPath             bool              `gorm:"default:false"`
	PreserveHost          bool              `gorm:"default:false"`
	RetryAttempts         int               `gorm:"default:0"`
	PluginChain           PluginChainJSON   `gorm:"type:jsonb"`
	Active                bool              `gorm:"default:true"`
	Public                bool              `gorm:"default:false"`
	CreatedAt             time.Time
	UpdatedAt             time.Time
	LoadBalancingStrategy string `gorm:"default:'round_robin'"`
}

// TargetsJSON implements SQL/JSON conversion for []types.Target
type TargetsJSON []types.Target

// Value implements the driver.Valuer interface
func (t TargetsJSON) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	return json.Marshal(t)
}

// Scan implements the sql.Scanner interface
func (t *TargetsJSON) Scan(value interface{}) error {
	if value == nil {
		*t = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &t)
	}
	return json.Unmarshal(bytes, &t)
}

// MethodsJSON implements SQL/JSON conversion for []string
type MethodsJSON []string

// Value implements the driver.Valuer interface
func (m MethodsJSON) Value() (driver.Value, error) {
	if m == nil {
		return nil, nil
	}
	return json.Marshal(m)
}

// Scan implements the sql.Scanner interface
func (m *MethodsJSON) Scan(value interface{}) error {
	if value == nil {
		*m = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &m)
	}
	return json.Unmarshal(bytes, &m)
}

// PluginChainJSON implements SQL/JSON conversion for []types.PluginConfig
type PluginChainJSON []types.PluginConfig

// Value implements the driver.Valuer interface
func (p PluginChainJSON) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

// Scan implements the sql.Scanner interface
func (p *PluginChainJSON) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &p)
	}
	return json.Unmarshal(bytes, &p)
}

// HeadersJSON implements SQL/JSON conversion for map[string]string
type HeadersJSON map[string]string

// Value implements the driver.Valuer interface
func (h HeadersJSON) Value() (driver.Value, error) {
	if h == nil {
		return nil, nil
	}
	return json.Marshal(h)
}

// Scan implements the sql.Scanner interface
func (h *HeadersJSON) Scan(value interface{}) error {
	if value == nil {
		*h = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &h)
	}
	return json.Unmarshal(bytes, &h)
}

// TableName specifies the table name for GORM
func (ForwardingRule) TableName() string {
	return "forwarding_rules"
}
