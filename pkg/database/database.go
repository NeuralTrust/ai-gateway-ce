package database

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/models"

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
		&models.Service{},
		&models.Upstream{},
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
