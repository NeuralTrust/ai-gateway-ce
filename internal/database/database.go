package database

import (
	"context"
	"fmt"

	"ai-gateway-ce/internal/models"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DB struct {
	*gorm.DB
}

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

func NewDB(cfg *Config) (*DB, error) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName, cfg.SSLMode)

	gormDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error).LogMode(logger.Info).LogMode(logger.Warn),
	})
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

	return &DB{
		DB: gormDB,
	}, nil
}

func (db *DB) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// IsSubdomainAvailable checks if a subdomain is available
func (db *DB) IsSubdomainAvailable(ctx context.Context, subdomain string) (bool, error) {
	var count int64
	err := db.DB.Model(&Gateway{}).Where("subdomain = ?", subdomain).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check subdomain: %w", err)
	}
	return count == 0, nil
}

// Add other GORM-based methods as needed...
