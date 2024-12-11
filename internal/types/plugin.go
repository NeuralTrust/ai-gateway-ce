package types

// BasePlugin provides common functionality for all plugins
type BasePlugin struct {
	FieldMapper
}

// ParseFieldMaps is a helper function to parse field mappings from plugin settings
func ParseFieldMaps(settings map[string]interface{}) []FieldMapping {
	var fieldMaps []FieldMapping
	if maps, ok := settings["field_maps"].([]interface{}); ok {
		for _, m := range maps {
			if mapData, ok := m.(map[string]interface{}); ok {
				fieldMap := FieldMapping{
					Source: mapData["source"].(string),
				}
				if dest, ok := mapData["destination"].(string); ok {
					fieldMap.Destination = dest
				}
				fieldMaps = append(fieldMaps, fieldMap)
			}
		}
	}
	return fieldMaps
}

type Plugin interface {
	Name() string
	Priority() int
	Stage() ExecutionStage
	Parallel() bool
	ProcessRequest(reqCtx *RequestContext, respCtx *ResponseContext) error
	ProcessResponse(respCtx *ResponseContext) error
	Configure(config PluginConfig) error
}
