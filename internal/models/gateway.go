package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type Gateway struct {
	ID              string         `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name            string         `json:"name" gorm:"not null"`
	Subdomain       string         `json:"subdomain" gorm:"uniqueIndex:idx_gateways_subdomain;not null"`
	ApiKey          string         `json:"api_key"`
	Status          string         `json:"status" gorm:"not null;default:'active'"`
	Tier            string         `json:"tier" gorm:"not null"`
	EnabledPlugins  pq.StringArray `json:"enabled_plugins" gorm:"type:text[]"`
	RequiredPlugins JSONMap        `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time      `json:"created_at" gorm:"not null;default:current_timestamp"`
	UpdatedAt       time.Time      `json:"updated_at" gorm:"not null;default:current_timestamp"`
}

// TableName specifies the table name for GORM
func (Gateway) TableName() string {
	return "gateways"
}

// BeforeCreate hook to ensure ID is set
func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = EmptyJSONMap()
	}
	return nil
}

// BeforeUpdate hook to update timestamps
func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = EmptyJSONMap()
	}
	return nil
}

// AfterFind hook to ensure RequiredPlugins is initialized
func (g *Gateway) AfterFind(tx *gorm.DB) error {
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = EmptyJSONMap()
	}
	return nil
}

// ToPluginConfigMap converts the required plugins to a map
func (g *Gateway) ToPluginConfigMap() (map[string]interface{}, error) {
	if g.RequiredPlugins == nil {
		return make(map[string]interface{}), nil
	}
	return g.RequiredPlugins, nil
}
