package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	t.Run("Valid Config", func(t *testing.T) {
		// Save current working directory
		currentDir, err := os.Getwd()
		assert.NoError(t, err)
		defer os.Chdir(currentDir)

		// Create a temporary directory and change to it
		tmpDir := t.TempDir()
		err = os.Chdir(tmpDir)
		assert.NoError(t, err)

		// Create config directory
		err = os.MkdirAll("config", 0755)
		assert.NoError(t, err)

		// Create main config.yaml
		configContent := `
server:
  admin_port: 8080
  proxy_port: 8081
  base_domain: "example.com"
  log_level: "debug"

database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "postgres"
  dbname: "aigateway"
  sslmode: "disable"

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0
`
		err = os.WriteFile(filepath.Join("config", "config.yaml"), []byte(configContent), 0644)
		assert.NoError(t, err)

		// Create providers.yaml
		providersContent := `
providers:
  openai:
    name: openai
    base_url: "https://api.openai.com"
    endpoints:
      /v1/chat/completions:
        path: "/v1/chat/completions"

  anthropic:
    name: anthropic
    base_url: "https://api.anthropic.com"
    endpoints:
      /v1/messages:
        path: "/v1/messages"
`
		err = os.WriteFile(filepath.Join("config", "providers.yaml"), []byte(providersContent), 0644)
		assert.NoError(t, err)

		// Load config
		err = Load()
		assert.NoError(t, err)

		cfg := GetConfig()
		assert.NotNil(t, cfg)
		assert.Equal(t, "example.com", cfg.Server.BaseDomain)
		assert.Equal(t, 8080, cfg.Server.AdminPort)
		assert.Equal(t, 8081, cfg.Server.ProxyPort)
		assert.Equal(t, "localhost", cfg.Database.Host)
		assert.Equal(t, 5432, cfg.Database.Port)
		assert.Equal(t, "postgres", cfg.Database.User)
		assert.Equal(t, "postgres", cfg.Database.Password)
		assert.Equal(t, "aigateway", cfg.Database.DBName)
		assert.Equal(t, "disable", cfg.Database.SSLMode)

		// Test provider config
		assert.NotNil(t, cfg.Providers.Providers["openai"])
		assert.Equal(t, "https://api.openai.com", cfg.Providers.Providers["openai"].BaseURL)
		assert.Equal(t, "/v1/chat/completions", cfg.Providers.Providers["openai"].Endpoints["/v1/chat/completions"].Path)

		assert.Equal(t, "anthropic", cfg.Providers.Providers["anthropic"].Name)
		assert.Equal(t, "https://api.anthropic.com", cfg.Providers.Providers["anthropic"].BaseURL)
		assert.Equal(t, "/v1/messages", cfg.Providers.Providers["anthropic"].Endpoints["/v1/messages"].Path)
	})
}
