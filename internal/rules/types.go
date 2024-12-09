package rules

// PluginConfig represents configuration for plugins
type PluginConfig struct {
	Name     string                 `json:"name"`
	Enabled  bool                   `json:"enabled"`
	Priority int                    `json:"priority"`
	Stage    string                 `json:"stage"`
	Settings map[string]interface{} `json:"settings"`
	Parallel bool                   `json:"parallel"`
}

// Common plugin stages
const (
	StagePreRequest   = "pre_request"
	StagePostRequest  = "post_request"
	StagePreResponse  = "pre_response"
	StagePostResponse = "post_response"
)

// Common plugin names
const (
	PluginRateLimiter       = "rate_limiter"
	PluginContentValidator  = "content_validator"
	PluginSecurityValidator = "security_validator"
	PluginExternalValidator = "external_validator"
)
