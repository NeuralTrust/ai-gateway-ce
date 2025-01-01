package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"ai-gateway-ce/pkg/cache"
	"ai-gateway-ce/pkg/common"
	"ai-gateway-ce/pkg/config"
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

// syncWriter wraps a buffered writer and ensures each write is flushed
type syncWriter struct {
	writer *bufio.Writer
	file   *os.File
	mu     sync.Mutex
}

// Write implements io.Writer
func (w *syncWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Write the data
	n, err = w.writer.Write(p)
	if err != nil {
		return n, err
	}

	// Ensure the write is flushed to disk
	if err = w.writer.Flush(); err != nil {
		return n, err
	}

	// Sync to disk to ensure durability
	return n, w.file.Sync()
}

// ConsoleHook is a logrus hook that writes to stdout
type ConsoleHook struct{}

// Fire implements logrus.Hook
func (h *ConsoleHook) Fire(entry *logrus.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

// Levels implements logrus.Hook
func (h *ConsoleHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime: "time",
			logrus.FieldKeyMsg:  "msg",
		},
	})

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

	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("logs", 0755); err != nil {
		log.Fatalf("Failed to create logs directory: %v", err)
	}

	// Open log file with sync writes
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file %s: %v", logFile, err)
	}
	defer file.Close()

	// Create a buffered writer with a larger buffer size
	writer := bufio.NewWriterSize(file, 32*1024) // 32KB buffer
	defer writer.Flush()

	// Create a synchronized writer that ensures atomic writes
	syncedWriter := &syncWriter{
		writer: writer,
		file:   file,
	}

	// Set the logger output to the file
	logger.SetOutput(syncedWriter)

	// In debug mode, add a hook for stdout
	if os.Getenv("LOG_LEVEL") == "debug" {
		logger.AddHook(&ConsoleHook{})
	}

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
		DBName:   config.Database.DBName,
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

	var srv server.Server
	switch serverType {
	case "admin":
		srv = server.NewAdminServer(config, cacheInstance, repo, logger)
	case "proxy":
		srv = server.NewProxyServer(
			config,
			cacheInstance,
			repo,
			logger,
			false, // debug mode
		)
	default:
		logger.Fatalf("Unknown server type: %s", serverType)
	}

	if err := srv.Run(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

func loadConfig() (*config.Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var config config.Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}
