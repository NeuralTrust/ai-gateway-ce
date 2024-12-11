package models

import (
	"ai-gateway-ce/internal/types"
	"database/sql/driver"
	"encoding/json"
)

// JSONMap is a custom type for handling JSON data
type JSONMap map[string]interface{}

// Value implements the driver.Valuer interface
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONMap)
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), &j)
	}
	return json.Unmarshal(bytes, &j)
}

// String returns the JSON string representation
func (j JSONMap) String() string {
	b, _ := json.Marshal(j)
	return string(b)
}

// IsValid checks if the JSON map is valid
func (j JSONMap) IsValid() bool {
	if j == nil {
		return false
	}
	_, err := json.Marshal(j)
	return err == nil
}

// ToBytes converts the JSONMap to bytes
func (j JSONMap) ToBytes() []byte {
	b, _ := json.Marshal(j)
	return b
}

// ToPluginConfigMap converts the JSONMap to a map of PluginConfig
func (j JSONMap) ToPluginConfigMap() (map[string]types.PluginConfig, error) {
	result := make(map[string]types.PluginConfig)
	if j == nil {
		return result, nil
	}

	for k, v := range j {
		if configMap, ok := v.(map[string]interface{}); ok {
			configBytes, err := json.Marshal(configMap)
			if err != nil {
				continue
			}
			var pluginConfig types.PluginConfig
			if err := json.Unmarshal(configBytes, &pluginConfig); err != nil {
				continue
			}
			result[k] = pluginConfig
		}
	}
	return result, nil
}

// FromBytes creates a JSONMap from bytes
func FromBytes(data []byte) (JSONMap, error) {
	var j JSONMap
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, err
	}
	return j, nil
}

// EmptyJSONMap returns an empty JSONMap
func EmptyJSONMap() JSONMap {
	return make(JSONMap)
}
