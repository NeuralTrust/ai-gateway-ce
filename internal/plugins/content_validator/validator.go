package content_validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"ai-gateway/internal/plugins"
)

type ContentValidator struct {
	allowedTypes []string
	maxSize      int64
	fields       []string // Fields to validate/forward
}

type Config struct {
	AllowedTypes []string `json:"allowed_types"`
	MaxSize      int64    `json:"max_size"`
	Fields       []string `json:"fields"` // Fields to include
}

func NewContentValidator(config Config) *ContentValidator {
	return &ContentValidator{
		allowedTypes: config.AllowedTypes,
		maxSize:      config.MaxSize,
		fields:       config.Fields,
	}
}

func (v *ContentValidator) Name() string {
	return "content_validator"
}

func (v *ContentValidator) Priority() int {
	return 1
}

func (v *ContentValidator) Stage() plugins.ExecutionStage {
	return plugins.PreRequest
}

func (v *ContentValidator) Parallel() bool {
	return true
}

func (v *ContentValidator) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) error {
	// Validate content type
	contentType := reqCtx.OriginalRequest.Header.Get("Content-Type")
	valid := false
	for _, allowed := range v.allowedTypes {
		if strings.HasPrefix(contentType, allowed) {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid content type: %s", contentType)
	}

	// Read and parse the original request body
	body, err := io.ReadAll(reqCtx.OriginalRequest.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the original body
	reqCtx.OriginalRequest.Body = io.NopCloser(strings.NewReader(string(body)))

	// Parse JSON body
	var requestBody map[string]interface{}
	if err := json.Unmarshal(body, &requestBody); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}

	// Store the full body in context
	reqCtx.RequestBody = requestBody

	// Filter fields if specified
	if len(v.fields) > 0 {
		filteredBody := make(map[string]interface{})
		for _, field := range v.fields {
			if value, exists := requestBody[field]; exists {
				filteredBody[field] = value
			}
		}

		// Create new JSON body with only selected fields
		newBody, err := json.Marshal(filteredBody)
		if err != nil {
			return fmt.Errorf("failed to marshal filtered body: %w", err)
		}

		// Update forward request with filtered body
		reqCtx.ForwardRequest.Body = io.NopCloser(strings.NewReader(string(newBody)))
		reqCtx.ForwardRequest.ContentLength = int64(len(newBody))
		reqCtx.ForwardRequest.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
	}

	return nil
}

func (v *ContentValidator) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	return nil
}
