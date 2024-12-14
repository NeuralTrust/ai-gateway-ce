package main

import (
	"io"
	"log"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/common"
	"ai-gateway-ce/pkg/database"
	"ai-gateway-ce/pkg/server"
)

type AppConfig struct {
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
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		Name     string `mapstructure:"name"`
		SSLMode  string `mapstructure:"ssl_mode"`
	} `mapstructure:"database"`
}

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Set log level
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.SetLevel(logrus.DebugLevel)
	}

	// Determine server type from command line
	serverType := "proxy"
	if len(os.Args) > 1 {
		serverType = os.Args[1]
	}

	// Set up logging to file
	var logFile string
	if serverType == "admin" {
		logFile = "logs/admin.log"
	} else {
		logFile = "logs/proxy.log"
	}

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", logFile, err)
	}
	defer file.Close()

	// Set up multi-writer for both file and stdout
	mw := io.MultiWriter(os.Stdout, file)
	logger.SetOutput(mw)

	// Load configuration
	config, err := loadConfig()
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.NewDB(&database.Config{
		Host:     config.Database.Host,
		Port:     config.Database.Port,
		User:     config.Database.User,
		Password: config.Database.Password,
		DBName:   config.Database.Name,
		SSLMode:  config.Database.SSLMode,
	})
	if err != nil {
		logger.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize cache with the database's GORM instance
	cacheConfig := common.CacheConfig{
		Host:     config.Redis.Host,
		Port:     config.Redis.Port,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	}
	cacheInstance, err := cache.NewCache(cacheConfig, db.DB)
	if err != nil {
		logger.Fatalf("Failed to initialize cache: %v", err)
	}

	// Initialize repository
	repo := database.NewRepository(db.DB, logger, cacheInstance)

	// Create server config
	serverConfig := &server.Config{
		AdminPort:  config.Server.AdminPort,
		ProxyPort:  config.Server.ProxyPort,
		BaseDomain: config.Server.BaseDomain,
	}

	var srv server.Server
	switch serverType {
	case "admin":
		srv = server.NewAdminServer(serverConfig, cacheInstance, repo, logger)
	case "proxy":
		srv = server.NewProxyServer(serverConfig, cacheInstance, repo, logger)
	default:
		logger.Fatalf("Unknown server type: %s", serverType)
	}

	if err := srv.Run(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() (*AppConfig, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config AppConfig
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
