package config

// Config holds all configuration for the application
type Config struct {
	BaseDomain string
	// Add other config fields as needed
}

func NewConfig() *Config {
	return &Config{
		BaseDomain: "example.com", // Set default or load from env
	}
}
