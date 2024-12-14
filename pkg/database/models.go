package database

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"ai-gateway-ce/pkg/types"
)

// Custom types for database serialization
type StringArray []string

func (a StringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(a)
}

func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	return json.Unmarshal(data, a)
}

// JSONMap represents a JSON object stored in the database
type JSONMap json.RawMessage

func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return "{}", nil
	}
	if !json.Valid([]byte(j)) {
		return "{}", nil
	}
	return string(j), nil
}

func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = JSONMap([]byte("{}"))
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	// Remove null bytes and validate JSON
	data = bytes.TrimRight(data, "\x00")
	if len(data) == 0 {
		*j = JSONMap([]byte("{}"))
		return nil
	}

	if !json.Valid(data) {
		*j = JSONMap([]byte("{}"))
		return nil
	}

	*j = JSONMap(data)
	return nil
}

// Convert to/from types.PluginConfig map
func (m JSONMap) ToPluginConfigMap() (map[string]types.PluginConfig, error) {
	if len(m) == 0 {
		return make(map[string]types.PluginConfig), nil
	}

	// Validate JSON structure
	if !json.Valid([]byte(m)) {
		return make(map[string]types.PluginConfig), nil
	}

	var rawMap map[string]types.PluginConfig
	if err := json.Unmarshal(json.RawMessage(m), &rawMap); err != nil {
		return make(map[string]types.PluginConfig), nil
	}

	// Validate each plugin config
	validatedMap := make(map[string]types.PluginConfig)
	for name, config := range rawMap {
		if name == "" {
			continue
		}
		// Ensure required fields have valid values
		if config.Name == "" {
			config.Name = name
		}
		if config.Settings == nil {
			config.Settings = make(map[string]interface{})
		}
		validatedMap[name] = config
	}

	return validatedMap, nil
}

func PluginConfigMapToJSONMap(m map[string]types.PluginConfig) (JSONMap, error) {
	if m == nil {
		return JSONMap([]byte("{}")), nil
	}

	// Validate and clean the map
	cleanMap := make(map[string]types.PluginConfig)
	for name, config := range m {
		if name == "" {
			continue
		}
		if config.Name == "" {
			config.Name = name
		}
		if config.Settings == nil {
			config.Settings = make(map[string]interface{})
		}
		cleanMap[name] = config
	}

	data, err := json.Marshal(cleanMap)
	if err != nil {
		return JSONMap([]byte("{}")), nil
	}
	return JSONMap(data), nil
}

// JSONArray represents a JSON array stored in the database
type JSONArray json.RawMessage

func (j JSONArray) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return string(j), nil
}

func (j *JSONArray) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var data []byte
	switch v := value.(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	default:
		return fmt.Errorf("unsupported type: %T", value)
	}

	*j = JSONArray(data)
	return nil
}
