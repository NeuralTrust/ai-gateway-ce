package server

// Config holds server configuration
type Config struct {
	Address    string // Server address (e.g., ":8080")
	AdminPort  int    // Port for admin server
	ProxyPort  int    // Port for proxy server
	BaseDomain string // Base domain for routing
}

// NewConfig creates a new Config with default values
func NewConfig() *Config {
	return &Config{
		Address:    ":8080",
		AdminPort:  8081,
		ProxyPort:  8080,
		BaseDomain: "localhost",
	}
}
