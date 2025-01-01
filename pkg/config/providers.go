package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// ProviderConfig represents the configuration for a single provider
type ProviderConfig struct {
	BaseURL   string            `yaml:"base_url"`
	Endpoints map[string]string `yaml:"endpoints"`
	ModelMap  map[string]string `yaml:"model_map"`
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

	// Debug: Print loaded config
	fmt.Printf("Loaded provider config: %+v\n", config)
	for name, provider := range config.Providers {
		fmt.Printf("Provider %s: base_url=%s\n", name, provider.BaseURL)
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
