package models

import (
	"time"

	"github.com/lib/pq"
)

type ForwardingRule struct {
	ID            string         `json:"id" gorm:"primaryKey"`
	GatewayID     string         `json:"gateway_id" gorm:"index"`
	Path          string         `json:"path"`
	Target        string         `json:"target"`
	Methods       pq.StringArray `json:"methods" gorm:"type:text[]"`
	Headers       pq.StringArray `json:"headers" gorm:"type:text[]"`
	StripPath     bool           `json:"strip_path"`
	PreserveHost  bool           `json:"preserve_host"`
	RetryAttempts int            `json:"retry_attempts"`
	PluginChain   JSONMap        `json:"plugin_chain" gorm:"type:jsonb"`
	Active        bool           `json:"active"`
	Public        bool           `json:"public"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (ForwardingRule) TableName() string {
	return "forwarding_rules"
}
