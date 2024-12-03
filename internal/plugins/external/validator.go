package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ai-gateway/internal/types"

	"github.com/sirupsen/logrus"
)

type ExternalValidator struct {
	logger     *logrus.Logger
	endpoint   string
	method     string
	headers    map[string]string
	timeout    time.Duration
	conditions []types.ResponseCondition
}

type ValidatorConfig struct {
	Endpoint    string                    `json:"endpoint"`
	Method      string                    `json:"method"`
	Headers     map[string]string         `json:"headers"`
	Timeout     string                    `json:"timeout"`
	Conditions  []types.ResponseCondition `json:"conditions"`
	RetryCount  int                       `json:"retry_count"`
	FailOnError bool                      `json:"fail_on_error"`
}

type ValidationResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func NewExternalValidator(logger *logrus.Logger, config types.PluginConfig) (*ExternalValidator, error) {
	logger.WithFields(logrus.Fields{
		"config": config,
	}).Debug("Creating external validator with config")

	// Get settings from config
	settings := config.Settings
	if settings == nil {
		return nil, fmt.Errorf("settings are required")
	}

	// Get endpoint
	endpoint, ok := settings["endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Get method (default to POST)
	method := "POST"
	if m, ok := settings["method"].(string); ok {
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
	if t, ok := settings["timeout"].(string); ok {
		if parsedTimeout, err := time.ParseDuration(t); err == nil {
			timeout = parsedTimeout
		}
	}

	// Get conditions from the plugin config root level
	var conditions []types.ResponseCondition
	if configConditions := config.Conditions; configConditions != nil {
		logger.WithFields(logrus.Fields{
			"raw_conditions": configConditions,
		}).Debug("Found conditions in config")

		for _, c := range configConditions {
			condition := types.ResponseCondition{
				Field:    c.Field,
				Operator: c.Operator,
				Value:    c.Value,
				StopFlow: c.StopFlow,
				Message:  c.Message,
			}
			conditions = append(conditions, condition)
			logger.WithFields(logrus.Fields{
				"parsed_condition": condition,
			}).Debug("Parsed condition")
		}
	}

	logger.WithFields(logrus.Fields{
		"endpoint":   endpoint,
		"method":     method,
		"headers":    headers,
		"timeout":    timeout,
		"conditions": conditions,
	}).Debug("External validator configuration loaded")

	return &ExternalValidator{
		logger:     logger,
		endpoint:   endpoint,
		method:     method,
		headers:    headers,
		timeout:    timeout,
		conditions: conditions,
	}, nil
}

func (v *ExternalValidator) Name() string {
	return "external_validator"
}

func (v *ExternalValidator) Priority() int {
	return 2
}

func (v *ExternalValidator) Stage() types.ExecutionStage {
	return types.PreRequest
}

func (v *ExternalValidator) Parallel() bool {
	return true
}

func (v *ExternalValidator) ProcessRequest(ctx context.Context, reqCtx *types.RequestContext) error {
	// Read and store the original request body
	var originalBody map[string]interface{}
	if reqCtx.OriginalRequest.Body != nil {
		if err := json.NewDecoder(reqCtx.OriginalRequest.Body).Decode(&originalBody); err != nil {
			v.logger.WithError(err).Error("Failed to read request body")
			return nil
		}
		// Reset body for further use
		bodyBytes, _ := json.Marshal(originalBody)
		reqCtx.OriginalRequest.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	v.logger.WithFields(logrus.Fields{
		"endpoint":      v.endpoint,
		"method":        v.method,
		"headers":       v.headers,
		"original_body": originalBody,
	}).Debug("Starting external validation")

	// Use original body directly instead of wrapping it
	payload, err := json.Marshal(originalBody)
	if err != nil {
		v.logger.WithError(err).Error("Failed to marshal validation request")
		return nil
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, v.method, v.endpoint, bytes.NewReader(payload))
	if err != nil {
		v.logger.WithError(err).Error("Failed to create validation request")
		return nil
	}

	// Set Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Set all headers from settings
	for headerKey, headerValue := range v.headers {
		req.Header.Set(headerKey, headerValue)
		v.logger.WithFields(logrus.Fields{
			"header": headerKey,
			"value":  headerValue,
		}).Debug("Setting header")
	}

	// Forward relevant headers from original request
	for k, values := range reqCtx.OriginalRequest.Header {
		if k != "Host" && k != "Content-Length" {
			req.Header[k] = values
		}
	}

	v.logger.WithFields(logrus.Fields{
		"url":     req.URL.String(),
		"method":  req.Method,
		"headers": req.Header,
	}).Debug("Executing validation request")

	// Execute request
	client := &http.Client{Timeout: v.timeout}
	resp, err := client.Do(req)
	if err != nil {
		v.logger.WithError(err).Error("Failed to execute validation request")
		return nil
	}
	defer resp.Body.Close()

	v.logger.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
	}).Debug("Received validation response")

	// Parse response
	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		v.logger.WithError(err).Error("Failed to read response body")
		return nil
	}

	v.logger.WithFields(logrus.Fields{
		"response_body": string(respBody),
		"conditions":    v.conditions,
	}).Debug("Evaluating response with conditions")

	if err := json.Unmarshal(respBody, &result); err != nil {
		v.logger.WithError(err).Error("Failed to parse validation response")
		return nil
	}

	// Check conditions
	for _, condition := range v.conditions {
		v.logger.WithFields(logrus.Fields{
			"condition": condition,
			"result":    result,
			"field":     condition.Field,
			"operator":  condition.Operator,
			"value":     condition.Value,
		}).Debug("Evaluating condition")

		// Split the field path and navigate through the JSON
		fieldPath := strings.Split(condition.Field, ".")
		currentValue := getNestedValue(result, fieldPath, v.logger)

		v.logger.WithFields(logrus.Fields{
			"field_path":    fieldPath,
			"current_value": currentValue,
		}).Debug("Retrieved value for condition")

		if currentValue != nil {
			matched := types.EvaluateCondition(condition, currentValue)
			v.logger.WithFields(logrus.Fields{
				"matched":   matched,
				"condition": condition,
				"value":     currentValue,
			}).Debug("Condition evaluation result")

			if matched && condition.StopFlow {
				response := ValidationResponse{
					Success: false,
					Message: condition.Message,
				}

				jsonResponse, err := json.Marshal(response)
				if err != nil {
					v.logger.WithError(err).Error("Failed to marshal validation response")
					return fmt.Errorf("failed to marshal validation response: %w", err)
				}

				reqCtx.ValidationResponse = jsonResponse
				reqCtx.StopForwarding = true
				return &types.PluginError{
					Message:    condition.Message,
					StatusCode: http.StatusOK,
				}
			}
		}
	}

	return nil
}

// Helper function to get nested value from map
func getNestedValue(data map[string]interface{}, path []string, logger *logrus.Logger) interface{} {
	if len(path) == 0 {
		return nil
	}

	current := data
	for i, key := range path {
		if i == len(path)-1 {
			// Last key, return the value
			return current[key]
		}

		// Not the last key, move deeper
		next, ok := current[key].(map[string]interface{})
		if !ok {
			logger.WithFields(logrus.Fields{
				"key":   key,
				"value": current[key],
				"path":  path,
			}).Debug("Failed to get nested value")
			return nil
		}
		current = next
	}

	return nil
}

func (v *ExternalValidator) ProcessResponse(ctx context.Context, respCtx *types.ResponseContext) error {
	return nil
}
