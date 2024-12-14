package models

import (
	"time"
)

// APIKey represents an API key in the database
type APIKey struct {
	ID        string     `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	GatewayID string     `json:"gateway_id" gorm:"column:gateway_id;index"`
	Name      string     `json:"name" gorm:"column:name"`
	Key       string     `json:"key" gorm:"column:key;index"`
	Active    bool       `json:"active" gorm:"column:active"`
	ExpiresAt *time.Time `json:"expires_at" gorm:"column:expires_at"`
	CreatedAt time.Time  `json:"created_at" gorm:"column:created_at"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"column:updated_at"`
}

func (APIKey) TableName() string {
	return "api_keys"
}
