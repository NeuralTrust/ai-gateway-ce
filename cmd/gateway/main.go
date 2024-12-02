package main

import (
	"log"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"ai-gateway/internal/cache"
	"ai-gateway/internal/server"
)

type Config struct {
	Server struct {
		AdminPort  int    `mapstructure:"admin_port"`
		ProxyPort  int    `mapstructure:"proxy_port"`
		BaseDomain string `mapstructure:"base_domain"`
	} `mapstructure:"server"`
	Redis struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`
}

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize cache
	cache, err := cache.NewCache(cache.Config{
		Host:     config.Redis.Host,
		Port:     config.Redis.Port,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}

	// Determine server type from command line
	serverType := "proxy"
	if len(os.Args) > 1 {
		serverType = os.Args[1]
	}

	switch serverType {
	case "admin":
		srv := server.NewAdminServer(&server.Config{
			AdminPort:  config.Server.AdminPort,
			BaseDomain: config.Server.BaseDomain,
		}, cache, logger)

		if err := srv.Run(); err != nil {
			log.Fatalf("Failed to start admin server: %v", err)
		}

	case "proxy":
		srv := server.NewProxyServer(&server.Config{
			ProxyPort:  config.Server.ProxyPort,
			BaseDomain: config.Server.BaseDomain,
		}, cache, logger)

		if err := srv.Run(); err != nil {
			log.Fatalf("Failed to start proxy server: %v", err)
		}

	default:
		log.Fatalf("Unknown server type: %s", serverType)
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
