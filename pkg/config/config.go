package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config holds all configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	AdminPort  int    `mapstructure:"admin_port"`
	ProxyPort  int    `mapstructure:"proxy_port"`
	Host       string `mapstructure:"host"`
	BaseDomain string `mapstructure:"base_domain"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
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
	viper.SetDefault("server.base_domain", "example.com")

	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.sslmode", "disable")

	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.password", "")
	viper.SetDefault("redis.db", 0)
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

// GetRedisConfig returns the redis configuration
func GetRedisConfig() RedisConfig {
	return globalConfig.Redis
}
