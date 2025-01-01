package types

type GatewayTraffic struct {
	Provider string `json:"provider"`
	Weight   int    `json:"weight"`
}

type GatewayProvider struct {
	Name                string            `json:"name"`
	Path                string            `json:"path"`
	StripPath           bool              `json:"strip_path"`
	Credentials         *Credentials      `json:"credentials"`
	FallbackProvider    string            `json:"fallback_provider,omitempty"`
	FallbackCredentials *Credentials      `json:"fallback_credentials"`
	FallbackModelMap    map[string]string `json:"fallback_model_map"`
	AllowedModels       []string          `json:"allowed_models"`
	PluginChain         []PluginConfig    `json:"plugin_chain"`
	Headers             map[string]string `json:"headers"`
}

type GatewaySettings struct {
	Traffic   []GatewayTraffic  `json:"traffic"`
	Providers []GatewayProvider `json:"providers"`
}

// Gateway represents a tenant's gateway configuration
type Gateway struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Subdomain       string          `json:"subdomain"`
	Status          string          `json:"status"`
	Type            string          `json:"type"`
	CreatedAt       string          `json:"created_at"`
	UpdatedAt       string          `json:"updated_at"`
	RequiredPlugins []PluginConfig  `json:"required_plugins"`
	Settings        GatewaySettings `json:"settings"`
}

type Target struct {
	URL      string `json:"url"`
	Weight   int    `json:"weight,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

// ForwardingRule represents a rule for forwarding requests
type ForwardingRule struct {
	ID                    string            `json:"id"`
	GatewayID             string            `json:"gateway_id"`
	Path                  string            `json:"path"`
	Targets               []Target          `json:"targets"`
	FallbackTargets       []Target          `json:"fallback_targets"`
	FallbackCredentials   *Credentials      `json:"fallback_credentials,omitempty"`
	Credentials           *Credentials      `json:"credentials,omitempty"`
	Methods               []string          `json:"methods"`
	Headers               map[string]string `json:"headers"`
	StripPath             bool              `json:"strip_path"`
	PreserveHost          bool              `json:"preserve_host"`
	RetryAttempts         int               `json:"retry_attempts"`
	PluginChain           []PluginConfig    `json:"plugin_chain"`
	Active                bool              `json:"active"`
	Public                bool              `json:"public"`
	CreatedAt             string            `json:"created_at"`
	UpdatedAt             string            `json:"updated_at"`
	LoadBalancingStrategy string            `json:"load_balancing_strategy"`
}

type Credentials struct {
	// Header-based auth
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// Parameter-based auth
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"` // "query" or "body"

	// Azure auth
	AzureUseManagedIdentity bool   `json:"azure_use_managed_identity,omitempty"`
	AzureClientID           string `json:"azure_client_id,omitempty"`
	AzureClientSecret       string `json:"azure_client_secret,omitempty"`
	AzureTenantID           string `json:"azure_tenant_id,omitempty"`

	// GCP auth
	GCPUseServiceAccount  bool   `json:"gcp_use_service_account,omitempty"`
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`

	// AWS auth
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`

	// General settings
	AllowOverride bool `json:"allow_override,omitempty"`
}
