package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"ai-gateway-ce/pkg/types"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PluginConfigSlice is a custom type for handling JSON serialization of []types.PluginConfig
type PluginConfigSlice []types.PluginConfig

// Scan implements the sql.Scanner interface
func (p *PluginConfigSlice) Scan(value interface{}) error {
	if value == nil {
		*p = make([]types.PluginConfig, 0)
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}

	return json.Unmarshal(bytes, p)
}

// Value implements the driver.Valuer interface
func (p PluginConfigSlice) Value() (driver.Value, error) {
	if p == nil {
		return json.Marshal([]types.PluginConfig{})
	}
	return json.Marshal(p)
}

type Gateway struct {
	ID              string            `json:"id" gorm:"primaryKey"`
	Name            string            `json:"name"`
	Subdomain       string            `json:"subdomain" gorm:"uniqueIndex"`
	Status          string            `json:"status"`
	RequiredPlugins PluginConfigSlice `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (Gateway) TableName() string {
	return "gateways"
}

// BeforeCreate hook to ensure ID is set and plugins are properly initialized
func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}

	// Initialize RequiredPlugins if nil
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}

	// Generate IDs for plugins if needed
	for i := range g.RequiredPlugins {
		if g.RequiredPlugins[i].ID == "" {
			g.RequiredPlugins[i].ID = uuid.New().String()
		}
	}

	return nil
}

// BeforeUpdate hook to update timestamps and ensure plugin IDs
func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()

	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}

	// Generate IDs for any new plugins
	for i := range g.RequiredPlugins {
		if g.RequiredPlugins[i].ID == "" {
			g.RequiredPlugins[i].ID = uuid.New().String()
		}
	}

	return nil
}

// AfterFind hook to ensure RequiredPlugins is initialized
func (g *Gateway) AfterFind(tx *gorm.DB) error {
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}
	return nil
}

// ToPluginConfigMap converts the required plugins to a map
func (g *Gateway) ToPluginConfigMap() ([]types.PluginConfig, error) {
	if g.RequiredPlugins == nil {
		return []types.PluginConfig{}, nil
	}

	return g.RequiredPlugins, nil
}

// Add helper methods for plugin management
func (g *Gateway) IsValid() bool {
	return g.RequiredPlugins != nil
}

func (g *Gateway) String() string {
	if g.RequiredPlugins == nil {
		return "{}"
	}
	bytes, _ := json.Marshal(g.RequiredPlugins)
	return string(bytes)
}
