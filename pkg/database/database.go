package database

import (
	"fmt"

	"ai-gateway-ce/pkg/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB represents the database connection
type DB struct {
	*gorm.DB
}

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// NewDB creates a new database connection
func NewDB(cfg *Config) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto-migrate the schema
	if err := gormDB.AutoMigrate(
		&models.Gateway{},
		&models.ForwardingRule{},
		&models.APIKey{},
	); err != nil {
		return nil, fmt.Errorf("failed to auto-migrate schema: %w", err)
	}

	return &DB{DB: gormDB}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// GetGateway retrieves a gateway by ID
func (db *DB) GetGateway(id uint) (*models.Gateway, error) {
	var gateway models.Gateway
	if err := db.First(&gateway, id).Error; err != nil {
		return nil, err
	}
	return &gateway, nil
}

// GetRule retrieves a rule by ID
func (db *DB) GetRule(id uint) (*models.ForwardingRule, error) {
	var rule models.ForwardingRule
	if err := db.First(&rule, id).Error; err != nil {
		return nil, err
	}
	return &rule, nil
}

// FindMatchingRule finds a rule matching the request path
func (db *DB) FindMatchingRule(gatewayID uint, path string) (*models.ForwardingRule, error) {
	var rule models.ForwardingRule
	if err := db.Where("gateway_id = ? AND path = ? AND is_active = true", gatewayID, path).
		Order("priority DESC").
		First(&rule).Error; err != nil {
		return nil, err
	}
	return &rule, nil
}
