package transformer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"ai-gateway/internal/plugins"
)

type TransformerConfig struct {
	Fields        []string               `json:"fields"`   // Fields to include
	Mappings      map[string]string      `json:"mappings"` // Field name mappings
	DefaultValues map[string]interface{} `json:"defaults"` // Default values for missing fields
}

type DataTransformer struct {
	config TransformerConfig
}

func NewDataTransformer(config TransformerConfig) *DataTransformer {
	return &DataTransformer{
		config: config,
	}
}

func (t *DataTransformer) Name() string {
	return "data_transformer"
}

func (t *DataTransformer) Priority() int {
	return 1
}

func (t *DataTransformer) Stage() plugins.ExecutionStage {
	return plugins.PreRequest
}

func (t *DataTransformer) Parallel() bool {
	return true
}

func (t *DataTransformer) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) error {
	// Read and parse the original request body
	body, err := io.ReadAll(reqCtx.OriginalRequest.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the original body for other plugins
	reqCtx.OriginalRequest.Body = io.NopCloser(strings.NewReader(string(body)))

	// Parse JSON body
	var originalData map[string]interface{}
	if err := json.Unmarshal(body, &originalData); err != nil {
		return fmt.Errorf("failed to parse JSON body: %w", err)
	}

	// Store original body in context
	reqCtx.RequestBody = originalData

	// Create transformed data
	transformedData := make(map[string]interface{})

	// Add selected fields
	for _, field := range t.config.Fields {
		if value, exists := originalData[field]; exists {
			// Apply field mapping if exists
			if newName, hasMappings := t.config.Mappings[field]; hasMappings {
				transformedData[newName] = value
			} else {
				transformedData[field] = value
			}
		} else if defaultValue, hasDefault := t.config.DefaultValues[field]; hasDefault {
			// Use default value if field is missing
			transformedData[field] = defaultValue
		}
	}

	// Store transformed data in metadata instead
	reqCtx.Metadata["transformed_body"] = transformedData

	// Create new JSON body for the forward request
	newBody, err := json.Marshal(transformedData)
	if err != nil {
		return fmt.Errorf("failed to marshal transformed body: %w", err)
	}

	// Update forward request with transformed body
	reqCtx.ForwardRequest.Body = io.NopCloser(strings.NewReader(string(newBody)))
	reqCtx.ForwardRequest.ContentLength = int64(len(newBody))
	reqCtx.ForwardRequest.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

	return nil
}

func (t *DataTransformer) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	return nil // Response transformation could be implemented if needed
}
