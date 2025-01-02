package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Gateway struct {
	ID              string           `json:"id" gorm:"primaryKey"`
	Name            string           `json:"name"`
	Subdomain       string           `json:"subdomain" gorm:"uniqueIndex"`
	Status          string           `json:"status"`
	RequiredPlugins PluginChainJSON  `json:"required_plugins" gorm:"type:jsonb"`
	ForwardingRules []ForwardingRule `json:"forwarding_rules" gorm:"foreignKey:GatewayID"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	return g.Validate()
}

func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()
	return g.Validate()
}

func (g *Gateway) Validate() error {
	if g.Name == "" {
		return fmt.Errorf("name is required")
	}

	if g.Subdomain == "" {
		return fmt.Errorf("subdomain is required")
	}

	if g.Status == "" {
		g.Status = "active"
	}

	return nil
}

func (g *Gateway) TableName() string {
	return "gateways"
}

// Include all Gateway-related methods
