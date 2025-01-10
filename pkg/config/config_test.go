package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	t.Run("Valid Config", func(t *testing.T) {
		// Create a temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "config.yaml")

		configContent := `
server:
  admin_port: 8080
  proxy_port: 8081
  base_domain: "example.com"

database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "postgres"
  name: "aigateway"
  ssl_mode: "disable"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
"
`
		err := os.WriteFile(configPath, []byte(configContent), 0644)
		assert.NoError(t, err)

		// Set config path
		os.Setenv("CONFIG_PATH", tmpDir)
		defer os.Unsetenv("CONFIG_PATH")

		// Load config
		if err := Load(); err != nil {
			t.Fatalf("Failed to load config: %v", err)
		}
		cfg := GetConfig()
		assert.NoError(t, err)
		assert.NotEmpty(t, cfg.Server.BaseDomain)
		assert.NotZero(t, cfg.Server.AdminPort)
		assert.NotZero(t, cfg.Server.ProxyPort)
		assert.NotEmpty(t, cfg.Database.Host)
		assert.NotEmpty(t, cfg.Database.User)
		assert.NotZero(t, cfg.Database.Port)
		assert.NotEmpty(t, cfg.Database.Password)
		assert.NotEmpty(t, cfg.Database.DBName)
		assert.NotEmpty(t, cfg.Database.SSLMode)
	})
}
