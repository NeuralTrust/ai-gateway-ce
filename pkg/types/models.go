package types

// Gateway represents a tenant's gateway configuration
type Gateway struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Subdomain       string         `json:"subdomain"`
	Status          string         `json:"status"`
	Tier            string         `json:"tier"`
	CreatedAt       string         `json:"created_at"`
	UpdatedAt       string         `json:"updated_at"`
	EnabledPlugins  []string       `json:"enabled_plugins"`
	RequiredPlugins []PluginConfig `json:"required_plugins"`
}

// ForwardingRule represents a rule for forwarding requests
type ForwardingRule struct {
	ID            string            `json:"id"`
	GatewayID     string            `json:"gateway_id"`
	Path          string            `json:"path"`
	Target        string            `json:"target"`
	Methods       []string          `json:"methods"`
	Headers       map[string]string `json:"headers"`
	StripPath     bool              `json:"strip_path"`
	PreserveHost  bool              `json:"preserve_host"`
	RetryAttempts int               `json:"retry_attempts"`
	PluginChain   []PluginConfig    `json:"plugin_chain"`
	Active        bool              `json:"active"`
	Public        bool              `json:"public"`
	CreatedAt     string            `json:"created_at"`
	UpdatedAt     string            `json:"updated_at"`
}

type APIKey struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Key   string `json:"key"`
	Group string `json:"group"`
}
