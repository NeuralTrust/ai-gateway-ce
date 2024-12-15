package external_validator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ai-gateway-ce/pkg/types"

	"github.com/sirupsen/logrus"
)

type ExternalValidator struct {
	client *http.Client
}

type FieldMap struct {
	Source      string `mapstructure:"source"`
	Destination string `mapstructure:"destination"`
}

type Condition struct {
	Field    string      `mapstructure:"field"`
	Operator string      `mapstructure:"operator"`
	Value    interface{} `mapstructure:"value"`
	StopFlow bool        `mapstructure:"stop_flow"`
	Message  string      `mapstructure:"message"`
}

func New() *ExternalValidator {
	return &ExternalValidator{
		client: &http.Client{},
	}
}

func (v *ExternalValidator) Name() string {
	return "external_validator"
}

func (v *ExternalValidator) Stages() []types.Stage {
	return []types.Stage{types.PreRequest}
}

type ExternalValidatorValidator struct{}

func (v *ExternalValidatorValidator) ValidateConfig(config types.PluginConfig) error {
	if config.Stage != types.PreRequest {
		return fmt.Errorf("external validator must be in pre_request stage")
	}

	settings := config.Settings

	// Validate endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return fmt.Errorf("external validator requires 'endpoint' configuration")
	}

	// Validate URL format
	if _, err := url.Parse(endpoint); err != nil {
		return fmt.Errorf("invalid endpoint URL format: %v", err)
	}

	// Validate timeout (optional)
	if timeout, exists := settings["timeout"].(string); exists {
		if _, err := time.ParseDuration(timeout); err != nil {
			return fmt.Errorf("invalid timeout format: %v", err)
		}
	}

	return nil
}

func (v *ExternalValidator) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	logger := ctx.Value("logger").(*logrus.Logger)

	settings := cfg.Settings
	if settings == nil {
		logger.WithError(fmt.Errorf("settings are required")).Error("External validator settings missing")
		return nil, fmt.Errorf("settings are required")
	}
	// Get endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Get method (default to POST)
	method := "POST"
	if m, ok := settings["method"].(string); ok && m != "" {
		method = m
	}

	// Get headers
	headers := make(map[string]string)
	if h, ok := settings["headers"].(map[string]interface{}); ok {
		for k, v := range h {
			if strVal, ok := v.(string); ok {
				headers[k] = strVal
			}
		}
	}

	// Get timeout (default to 5s)
	timeout := 5 * time.Second
	if t, ok := settings["timeout"].(string); ok && t != "" {
		if parsed, err := time.ParseDuration(t); err == nil {
			timeout = parsed
		}
	}

	// Get field mappings
	var fieldMaps []FieldMap
	if maps, ok := settings["field_maps"].([]interface{}); ok {
		for _, m := range maps {
			if mapData, ok := m.(map[string]interface{}); ok {
				fieldMap := FieldMap{
					Source:      mapData["source"].(string),
					Destination: mapData["destination"].(string),
				}
				fieldMaps = append(fieldMaps, fieldMap)
			}
		}
	}

	// Get conditions
	var conditions []Condition
	if conds, ok := settings["conditions"].([]interface{}); ok {
		for _, c := range conds {
			if condMap, ok := c.(map[string]interface{}); ok {
				condition := Condition{
					Field:    condMap["field"].(string),
					Operator: condMap["operator"].(string),
					Value:    condMap["value"],
					StopFlow: condMap["stop_flow"].(bool),
				}
				if msg, ok := condMap["message"].(string); ok {
					condition.Message = msg
				}
				conditions = append(conditions, condition)
			}
		}
	}

	// Parse request body
	var originalBody map[string]interface{}
	if len(req.Body) > 0 {
		if err := json.Unmarshal(req.Body, &originalBody); err != nil {
			return nil, fmt.Errorf("invalid request body: %w", err)
		}
	}

	// Apply field mappings
	validationReq := make(map[string]interface{})
	for _, mapping := range fieldMaps {
		switch mapping.Source {
		case "input":
			if value, ok := originalBody[mapping.Source]; ok {
				validationReq[mapping.Destination] = value
			}
		}
	}

	// Marshal request data
	reqBody, err := json.Marshal(validationReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal validation request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create validation request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	// Set timeout
	v.client.Timeout = timeout

	// Make request
	httpResp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, &types.PluginError{
			StatusCode: http.StatusBadGateway,
			Message:    "External validation failed",
			Err:        err,
		}
	}
	defer httpResp.Body.Close()

	// Parse response
	var validationResp map[string]interface{}
	if err := json.NewDecoder(httpResp.Body).Decode(&validationResp); err != nil {
		return nil, fmt.Errorf("failed to parse validation response: %w", err)
	}
	logger.WithFields(logrus.Fields{
		"validationResp": validationResp,
	}).Debug("Validation response")
	// Check conditions
	for _, condition := range conditions {
		value := getNestedValue(validationResp, strings.Split(condition.Field, "."))
		if value != nil {
			if matches := evaluateCondition(value, condition.Operator, condition.Value); matches && condition.StopFlow {
				return nil, &types.PluginError{
					StatusCode: http.StatusUnprocessableEntity,
					Message:    condition.Message,
					Err:        fmt.Errorf("validation failed"),
				}
			}
		}
	}

	return &types.PluginResponse{
		StatusCode: http.StatusOK,
		Message:    "Validation passed",
		Body:       validationResp,
	}, nil
}

func getNestedValue(data map[string]interface{}, path []string) interface{} {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			return current[key]
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else {
			return nil
		}
	}
	return nil
}

func evaluateCondition(actual interface{}, operator string, expected interface{}) bool {
	switch operator {
	case "eq":
		return actual == expected
	case "neq":
		return actual != expected
	case "gt":
		// Add numeric comparisons if needed
		return false
	default:
		return false
	}
}

func (v *ExternalValidator) Configure(cfg types.PluginConfig) error {
	return nil
}
