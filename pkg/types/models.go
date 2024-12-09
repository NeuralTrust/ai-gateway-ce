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
