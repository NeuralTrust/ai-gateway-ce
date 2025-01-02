package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type ForwardingRule struct {
	ID            string          `gorm:"primaryKey"`
	GatewayID     string          `gorm:"not null"`
	ServiceID     string          `gorm:"not null"`
	Path          string          `gorm:"not null"`
	Methods       MethodsJSON     `gorm:"type:jsonb"`
	Headers       HeadersJSON     `gorm:"type:jsonb"`
	StripPath     bool            `gorm:"default:false"`
	PreserveHost  bool            `gorm:"default:false"`
	PluginChain   PluginChainJSON `gorm:"type:jsonb"`
	Active        bool            `gorm:"default:true"`
	Public        bool            `gorm:"default:false"`
	RetryAttempts int             `gorm:"default:1"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

func (fr *ForwardingRule) BeforeCreate(tx *gorm.DB) error {
	if fr.ID == "" {
		fr.ID = uuid.New().String()
	}
	return fr.Validate()
}

func (fr *ForwardingRule) BeforeUpdate(tx *gorm.DB) error {
	fr.UpdatedAt = time.Now()
	return fr.Validate()
}

func (fr *ForwardingRule) Validate() error {
	if fr.Path == "" {
		return fmt.Errorf("path is required")
	}

	if fr.ServiceID == "" {
		return fmt.Errorf("service_id is required")
	}

	if len(fr.Methods) == 0 {
		return fmt.Errorf("at least one HTTP method is required")
	}

	validMethods := map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true,
	}

	for _, method := range fr.Methods {
		if !validMethods[method] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}

	return nil
}

// Include all the ForwardingRule-related methods
