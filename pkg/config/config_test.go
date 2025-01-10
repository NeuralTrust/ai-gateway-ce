package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	// Test loading valid config
	t.Run("Valid Config", func(t *testing.T) {
		err := Load()
		assert.NoError(t, err)
		assert.NotNil(t, globalConfig)

		// Verify basic config fields
		assert.NotEmpty(t, globalConfig.Redis.Host)
		assert.NotEmpty(t, globalConfig.Database.Host)
		// Verify server config fields
		assert.NotEmpty(t, globalConfig.Server.AdminPort)
		assert.NotEmpty(t, globalConfig.Server.ProxyPort)
		assert.NotEmpty(t, globalConfig.Server.BaseDomain)
		// Verify database config fields
		assert.NotEmpty(t, globalConfig.Database.Host)
		assert.NotEmpty(t, globalConfig.Database.Port)
		assert.NotEmpty(t, globalConfig.Database.User)
		assert.NotEmpty(t, globalConfig.Database.Password)
		assert.NotEmpty(t, globalConfig.Database.DBName)
	})
}
