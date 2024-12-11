package types

type PluginConfig struct {
	Enabled  bool                   `json:"enabled"`
	Settings map[string]interface{} `json:"settings"`
}

type Gateway struct {
	ID        string                  `json:"id"`
	Name      string                  `json:"name"`
	Subdomain string                  `json:"subdomain"`
	Tier      string                  `json:"tier"`
	Plugins   map[string]PluginConfig `json:"plugins"`
	APIKey    string                  `json:"api_key"`
}

// Rule defines a forwarding rule configuration
type Rule struct {
	ID             string                  `json:"id"`
	Path           string                  `json:"path"`
	Target         string                  `json:"target"`
	Methods        []string                `json:"methods"`
	StripPath      bool                    `json:"strip_path"`
	RequiredGroups []string                `json:"required_groups"`
	Plugins        map[string]PluginConfig `json:"plugins"`
}

type ConsumerGroup struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings"`
}

type APIKey struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Key   string `json:"key"`
	Group string `json:"group"`
}
