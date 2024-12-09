package types

import "strings"

// FieldMapping defines how fields should be mapped from source to destination
type FieldMapping struct {
	Source      string `json:"source"`      // Path to field in original request
	Destination string `json:"destination"` // Path in mapped request
}

// FieldMapper provides field mapping functionality for plugins
type FieldMapper struct {
	FieldMaps []FieldMapping `json:"field_maps"`
}

// MapFields creates a new map with only the specified fields mapped from the source
func (fm *FieldMapper) MapFields(source map[string]interface{}) map[string]interface{} {
	if len(fm.FieldMaps) == 0 {
		return source
	}

	result := make(map[string]interface{})
	for _, mapping := range fm.FieldMaps {
		value := getFieldValue(source, mapping.Source)
		if value != nil {
			destPath := mapping.Destination
			if destPath == "" {
				destPath = mapping.Source
			}
			setFieldValue(result, destPath, value)
		}
	}
	return result
}

func getFieldValue(data map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			return current[part]
		}

		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}
	return nil
}

func setFieldValue(data map[string]interface{}, path string, value interface{}) {
	parts := strings.Split(path, ".")
	current := data

	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return
		}

		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else {
			next = make(map[string]interface{})
			current[part] = next
			current = next
		}
	}
}
