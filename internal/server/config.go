package server

// Config holds all server configuration
type Config struct {
	AdminPort  int    `mapstructure:"admin_port"`
	ProxyPort  int    `mapstructure:"proxy_port"`
	BaseDomain string `mapstructure:"base_domain"`
}
