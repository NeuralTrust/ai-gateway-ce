package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config holds all configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	AdminPort int    `mapstructure:"admin_port"`
	ProxyPort int    `mapstructure:"proxy_port"`
	Host      string `mapstructure:"host"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

var (
	// Global configuration
	globalConfig Config
)

// Load loads the configuration from config files
func Load() error {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Set defaults
	setDefaults()

	// Read the config file
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Unmarshal the config
	if err := viper.Unmarshal(&globalConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

// setDefaults sets default values for configuration
func setDefaults() {
	viper.SetDefault("server.admin_port", 8080)
	viper.SetDefault("server.proxy_port", 8081)
	viper.SetDefault("server.host", "0.0.0.0")

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")
}

// GetConfig returns the global configuration
func GetConfig() *Config {
	return &globalConfig
}

// GetDatabaseConfig returns the database configuration
func GetDatabaseConfig() DatabaseConfig {
	return globalConfig.Database
}

// GetServerConfig returns the server configuration
func GetServerConfig() ServerConfig {
	return globalConfig.Server
}
