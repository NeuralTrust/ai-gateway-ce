package validator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Validator struct {
	maxBodySize    int64
	allowedTypes   map[string]bool
	requiredFields map[string][]string
}

type Config struct {
	MaxBodySize    int64    `json:"max_body_size"`
	AllowedTypes   []string `json:"allowed_types"`
	RequiredFields []string `json:"required_fields"`
}

func NewValidator(config Config) *Validator {
	allowedTypes := make(map[string]bool)
	for _, t := range config.AllowedTypes {
		allowedTypes[t] = true
	}

	return &Validator{
		maxBodySize:  config.MaxBodySize,
		allowedTypes: allowedTypes,
	}
}

func (v *Validator) Name() string {
	return "validator"
}

func (v *Validator) Priority() int {
	return 0
}

func (v *Validator) ProcessRequest(ctx context.Context, req *http.Request) error {
	// Check content type
	contentType := req.Header.Get("Content-Type")
	if !v.allowedTypes[contentType] {
		return fmt.Errorf("content type %s not allowed", contentType)
	}

	// Check body size
	if req.ContentLength > v.maxBodySize {
		return fmt.Errorf("request body too large")
	}

	// Validate JSON body if applicable
	if strings.HasPrefix(contentType, "application/json") {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}

		// Restore body for later use
		req.Body = io.NopCloser(strings.NewReader(string(body)))

		var jsonBody map[string]interface{}
		if err := json.Unmarshal(body, &jsonBody); err != nil {
			return fmt.Errorf("invalid JSON body: %w", err)
		}
	}

	return nil
}

func (v *Validator) ProcessResponse(ctx context.Context, resp *http.Response) error {
	return nil
}
