package main

import (
	"log"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/plugins"
	"ai-gateway/internal/plugins/external"
	"ai-gateway/internal/server"
)

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize cache with proper config conversion
	cacheConfig := cache.Config{
		Host:     config.Redis.Host,
		Port:     config.Redis.Port,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	}

	cache, err := cache.NewCache(cacheConfig)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}

	// Initialize plugin registry
	pluginManager := plugins.NewRegistry()

	// Initialize external validator plugin
	externalValidator := external.NewExternalValidator(external.Config{
		Endpoint:   "https://your-validation-api.com/validate",
		AuthHeader: "Bearer your-api-key",
		Timeout:    5 * time.Second,
		RetryCount: 2,
	})
	pluginManager.Register(externalValidator)

	// Create and start server
	srv := server.NewServer(&server.Config{
		Port:       config.Server.Port,
		BaseDomain: config.Server.BaseDomain,
	}, cache, logger, pluginManager)

	if err := srv.Run(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

type Config struct {
	Server struct {
		Port       int    `mapstructure:"port"`
		BaseDomain string `mapstructure:"base_domain"`
	} `mapstructure:"server"`
	Redis struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`
}
