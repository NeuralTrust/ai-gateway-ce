package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProviderConfig represents the configuration for a single provider
type ProviderConfig struct {
	Name      string                    `yaml:"name"`
	BaseURL   string                    `yaml:"base_url"`
	Endpoints map[string]EndpointConfig `yaml:"endpoints"`
}

type EndpointConfig struct {
	Path   string          `yaml:"path"`
	Schema *ProviderSchema `yaml:"schema,omitempty"`
}

type ProviderSchema struct {
	IdentifyingKeys []string               `yaml:"identifying_keys"`
	RequestFormat   map[string]SchemaField `yaml:"request_format"`
	ResponseFormat  map[string]SchemaField `yaml:"response_format"`
}

type SchemaField struct {
	Type      string      `yaml:"type"` // string, array, object, number, boolean
	Required  bool        `yaml:"required"`
	Path      string      `yaml:"path"` // JSON path for mapping
	Default   interface{} `yaml:"default,omitempty"`
	Condition string      `yaml:"condition,omitempty"` // Condition for extracting value
}

// ProvidersConfig represents the configuration for all providers
type ProvidersConfig struct {
	Providers map[string]ProviderConfig `yaml:"providers"`
}

// LoadProviderConfig loads the provider configuration from the YAML file
func LoadProviderConfig() (*ProvidersConfig, error) {
	data, err := os.ReadFile("./config/providers.yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to read provider config: %w", err)
	}

	var config ProvidersConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal provider config: %w", err)
	}

	return &config, nil
}

// GetProviderConfig returns the configuration for a specific provider
func GetProviderConfig(name string) (*ProviderConfig, error) {
	config, err := LoadProviderConfig()
	if err != nil {
		return nil, err
	}

	provider, exists := config.Providers[name]
	if !exists {
		return nil, fmt.Errorf("provider %s not found in configuration", name)
	}

	return &provider, nil
}
