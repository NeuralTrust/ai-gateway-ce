package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"ai-gateway-ce/pkg/config"
	"ai-gateway-ce/pkg/types"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Credentials represents all possible authentication methods
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

// GatewaySettings is a custom type for handling JSON serialization of gateway settings
type GatewaySettings struct {
	Traffic   []GatewayTraffic  `json:"traffic"`
	Providers []GatewayProvider `json:"providers"`
}

// GatewayTraffic struct
type GatewayTraffic struct {
	Provider string `json:"provider"`
	Weight   int    `json:"weight"`
}

// GatewayProvider struct
type GatewayProvider struct {
	Name                string            `json:"name"`
	Path                string            `json:"path"`
	StripPath           bool              `json:"strip_path"`
	Credentials         CredentialsJSON   `json:"credentials"`
	FallbackProvider    string            `json:"fallback_provider"`
	FallbackCredentials CredentialsJSON   `json:"fallback_credentials"`
	PluginChain         []string          `json:"plugin_chain"`
	AllowedModels       []string          `json:"allowed_models"`
	FallbackModelMap    map[string]string `json:"fallback_model_map"`
	Headers             map[string]string `json:"headers"`
}

// Scan implements the sql.Scanner interface
func (s *GatewaySettings) Scan(value interface{}) error {
	if value == nil {
		*s = GatewaySettings{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}

	return json.Unmarshal(bytes, s)
}

// Value implements the driver.Valuer interface
func (s GatewaySettings) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// IsEmpty checks if GatewaySettings is empty
func (s GatewaySettings) IsEmpty() bool {
	return len(s.Traffic) == 0 && len(s.Providers) == 0
}

// PluginConfigJSON implements SQL/JSON conversion for []types.PluginConfig
type PluginConfigJSON []types.PluginConfig

// Value implements the driver.Valuer interface
func (p PluginConfigJSON) Value() (driver.Value, error) {
	if p == nil {
		return nil, nil
	}
	return json.Marshal(p)
}

// Scan implements the sql.Scanner interface
func (p *PluginConfigJSON) Scan(value interface{}) error {
	if value == nil {
		*p = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, p)
}

// Gateway represents a gateway in the database
type Gateway struct {
	ID              string           `json:"id" gorm:"primaryKey"`
	Name            string           `json:"name"`
	Subdomain       string           `json:"subdomain" gorm:"uniqueIndex"`
	Type            string           `json:"type"`
	Status          string           `json:"status"`
	Settings        GatewaySettings  `json:"settings" gorm:"type:jsonb"`
	ForwardingRules []ForwardingRule `json:"forwarding_rules" gorm:"foreignKey:GatewayID"`
	RequiredPlugins PluginConfigJSON `json:"required_plugins" gorm:"type:jsonb"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// TableName specifies the table name for GORM
func (Gateway) TableName() string {
	return "gateways"
}

// BeforeCreate hook to ensure ID is set and fields are properly initialized
func (g *Gateway) BeforeCreate(tx *gorm.DB) error {
	// Validate required fields
	if g.Type == "" {
		return fmt.Errorf("gateway type is required")
	}
	if g.Name == "" {
		return fmt.Errorf("gateway name is required")
	}
	if g.Subdomain == "" {
		return fmt.Errorf("gateway subdomain is required")
	}

	// Validate gateway type
	if g.Type != "models" && g.Type != "backends" {
		return fmt.Errorf("invalid gateway type: %s (must be 'models' or 'backends')", g.Type)
	}

	// Generate ID if not set
	if g.ID == "" {
		g.ID = uuid.New().String()
	}

	// Initialize Settings if empty
	if g.Settings.IsEmpty() {
		g.Settings = GatewaySettings{}
	}

	// Initialize RequiredPlugins if nil
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}

	// Generate forwarding rules for models type
	if g.Type == "models" {
		g.generateProviderRules()

		// Get the cacher from the context
		if cacher, ok := tx.Statement.Context.Value("cacher").(types.RulesCacher); ok {
			// Convert models.ForwardingRule to types.ForwardingRule
			apiRules := make([]types.ForwardingRule, len(g.ForwardingRules))
			for i, rule := range g.ForwardingRules {
				apiRules[i] = types.ForwardingRule{
					ID:                  rule.ID,
					GatewayID:           rule.GatewayID,
					Path:                rule.Path,
					Targets:             rule.Targets,
					Credentials:         rule.Credentials.ToCredentials(),
					FallbackCredentials: rule.FallbackCredentials.ToCredentials(),
					FallbackTargets:     rule.FallbackTargets,
					Methods:             rule.Methods,
					Headers:             rule.Headers,
					StripPath:           rule.StripPath,
					PreserveHost:        rule.PreserveHost,
					RetryAttempts:       rule.RetryAttempts,
					PluginChain:         rule.PluginChain,
					Active:              rule.Active,
					Public:              rule.Public,
					CreatedAt:           rule.CreatedAt.Format(time.RFC3339),
					UpdatedAt:           rule.UpdatedAt.Format(time.RFC3339),
				}
			}
			if err := cacher.UpdateRulesCache(tx.Statement.Context, g.ID, apiRules); err != nil {
				log.Printf("Failed to cache rules: %v", err)
				// Continue anyway as rules are saved in DB
			}
		}
	}

	// Generate IDs for plugins if needed
	for i := range g.RequiredPlugins {
		if g.RequiredPlugins[i].ID == "" {
			g.RequiredPlugins[i].ID = uuid.New().String()
		}
	}

	return nil
}

// BeforeUpdate hook to update timestamps and ensure plugin IDs
func (g *Gateway) BeforeUpdate(tx *gorm.DB) error {
	g.UpdatedAt = time.Now()

	// Validate gateway type
	if g.Type != "models" && g.Type != "backends" {
		return fmt.Errorf("invalid gateway type: %s (must be 'models' or 'backends')", g.Type)
	}

	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}

	// Regenerate forwarding rules for models type
	if g.Type == "models" {
		g.generateProviderRules()
	}

	// Generate IDs for any new plugins
	for i := range g.RequiredPlugins {
		if g.RequiredPlugins[i].ID == "" {
			g.RequiredPlugins[i].ID = uuid.New().String()
		}
	}

	return nil
}

// AfterFind hook to ensure RequiredPlugins is initialized
func (g *Gateway) AfterFind(tx *gorm.DB) error {
	if g.RequiredPlugins == nil {
		g.RequiredPlugins = []types.PluginConfig{}
	}
	return nil
}

// ToPluginConfigMap converts the required plugins to a map
func (g *Gateway) ToPluginConfigMap() ([]types.PluginConfig, error) {
	if g.RequiredPlugins == nil {
		return []types.PluginConfig{}, nil
	}

	return g.RequiredPlugins, nil
}

// Add helper methods for plugin management
func (g *Gateway) IsValid() bool {
	return g.RequiredPlugins != nil
}

func (g *Gateway) String() string {
	if g.RequiredPlugins == nil {
		return "{}"
	}
	bytes, _ := json.Marshal(g.RequiredPlugins)
	return string(bytes)
}

func (g *Gateway) generateProviderRules() {
	if g.Type != "models" {
		return
	}

	providerConfig, err := config.LoadProviderConfig()
	if err != nil {
		log.Printf("Failed to load provider config: %v", err)
		return
	}

	var rules []ForwardingRule
	now := time.Now()

	// Generate rules for each provider in settings
	for _, provider := range g.Settings.Providers {
		// Get provider configuration for endpoint paths
		pConfig, ok := providerConfig.Providers[provider.Name]
		if !ok {
			continue
		}

		targetURL := pConfig.BaseURL

		// Find fallback provider if configured
		var fallbackProvider *GatewayProvider
		if provider.FallbackProvider != "" {
			for _, p := range g.Settings.Providers {
				if p.Name == provider.FallbackProvider {
					fallbackProvider = &p
					break
				}
			}
		}

		// Generate rules for each endpoint
		for _, path := range pConfig.Endpoints {
			var fallbackTargets TargetsJSON
			var fallbackCreds *types.Credentials

			if fallbackProvider != nil {
				// Get fallback provider config
				fallbackConfig, ok := providerConfig.Providers[fallbackProvider.Name]
				if ok {
					// Always use base URL from provider config for fallback
					fallbackTargets = TargetsJSON{{URL: fallbackConfig.BaseURL}}
					fallbackCreds = (*types.Credentials)(&fallbackProvider.Credentials)
				}
			}

			// Initialize headers map with provider's headers
			headers := HeadersJSON{}
			if provider.Headers != nil {
				for k, v := range provider.Headers {
					headers[k] = v
				}
			}

			rules = append(rules, ForwardingRule{
				ID:                  uuid.New().String(),
				GatewayID:           g.ID,
				Path:                provider.Path,
				Targets:             TargetsJSON{{URL: targetURL}},
				FallbackTargets:     fallbackTargets,
				Methods:             MethodsJSON{"POST"},
				Headers:             headers,
				StripPath:           provider.StripPath,
				PreserveHost:        false,
				RetryAttempts:       3,
				PluginChain:         PluginChainJSON{},
				Active:              true,
				Public:              false,
				CreatedAt:           now,
				UpdatedAt:           now,
				Credentials:         (*CredentialsJSON)(&provider.Credentials),
				FallbackCredentials: (*CredentialsJSON)(fallbackCreds),
			})

			log.Printf("Generated rule for %s: Path=%s, Target=%s, Fallback=%v",
				provider.Name, path, targetURL, fallbackTargets)
		}
	}

	g.ForwardingRules = rules
}
