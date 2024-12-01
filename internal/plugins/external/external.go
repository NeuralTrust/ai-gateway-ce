package external

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"ai-gateway/internal/plugins"

	"github.com/sirupsen/logrus"
)

type ExternalValidator struct {
	client     *http.Client
	endpoint   string
	authHeader string
	timeout    time.Duration
	retryCount int
	fields     []string
	logger     *logrus.Logger
}

type Config struct {
	Endpoint   string        `json:"endpoint"`
	AuthHeader string        `json:"auth_header"`
	Timeout    time.Duration `json:"timeout"`
	RetryCount int           `json:"retry_count"`
	Fields     []string      `json:"fields"` // Fields to validate
}

func NewExternalValidator(config Config, logger *logrus.Logger) *ExternalValidator {
	return &ExternalValidator{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		endpoint:   config.Endpoint,
		authHeader: config.AuthHeader,
		timeout:    config.Timeout,
		retryCount: config.RetryCount,
		fields:     config.Fields,
		logger:     logger,
	}
}

func (e *ExternalValidator) Name() string {
	return "external_validator"
}

func (e *ExternalValidator) Priority() int {
	return 0
}

func (e *ExternalValidator) Stage() plugins.ExecutionStage {
	return plugins.PreRequest
}

func (e *ExternalValidator) Parallel() bool {
	return true
}

func (e *ExternalValidator) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) error {
	e.logger.WithFields(logrus.Fields{
		"plugin":    "external_validator",
		"tenant_id": reqCtx.TenantID,
		"endpoint":  e.endpoint,
		"fields":    e.fields,
	}).Debug("Starting external validation")

	// Extract fields to validate
	dataToValidate := make(map[string]interface{})
	if len(e.fields) > 0 {
		for _, field := range e.fields {
			if value, exists := reqCtx.RequestBody[field]; exists {
				dataToValidate[field] = value
			}
		}
	} else {
		dataToValidate = reqCtx.RequestBody
	}

	e.logger.WithFields(logrus.Fields{
		"plugin":      "external_validator",
		"data_fields": len(dataToValidate),
	}).Debug("Prepared validation data")

	// Send validation request with retries
	var lastErr error
	for i := 0; i <= e.retryCount; i++ {
		err := e.sendValidationRequest(ctx, reqCtx, dataToValidate)
		if err == nil {
			e.logger.WithFields(logrus.Fields{
				"plugin":  "external_validator",
				"attempt": i + 1,
			}).Debug("Validation successful")
			return nil
		}

		lastErr = err
		e.logger.WithFields(logrus.Fields{
			"plugin":  "external_validator",
			"attempt": i + 1,
			"error":   err.Error(),
		}).Warn("Validation attempt failed")

		if i < e.retryCount {
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	e.logger.WithFields(logrus.Fields{
		"plugin": "external_validator",
		"error":  lastErr.Error(),
	}).Error("All validation attempts failed")

	return fmt.Errorf("validation failed after %d attempts: %w", e.retryCount+1, lastErr)
}

func (e *ExternalValidator) sendValidationRequest(ctx context.Context, reqCtx *plugins.RequestContext, data map[string]interface{}) error {
	// Prepare validation request
	validationReq := struct {
		TenantID string                 `json:"tenant_id"`
		Method   string                 `json:"method"`
		Path     string                 `json:"path"`
		Headers  map[string]string      `json:"headers"`
		Body     map[string]interface{} `json:"body"`
	}{
		TenantID: reqCtx.TenantID,
		Method:   reqCtx.OriginalRequest.Method,
		Path:     reqCtx.OriginalRequest.URL.Path,
		Headers:  make(map[string]string),
		Body:     data,
	}

	// Copy relevant headers
	for k, v := range reqCtx.OriginalRequest.Header {
		if len(v) > 0 {
			validationReq.Headers[k] = v[0]
		}
	}

	// Marshal validation request
	validationBody, err := json.Marshal(validationReq)
	if err != nil {
		return fmt.Errorf("failed to marshal validation request: %w", err)
	}

	// Create external validation request
	extReq, err := http.NewRequestWithContext(
		ctx,
		"POST",
		e.endpoint,
		bytes.NewReader(validationBody),
	)
	if err != nil {
		return fmt.Errorf("failed to create validation request: %w", err)
	}

	extReq.Header.Set("Content-Type", "application/json")
	if e.authHeader != "" {
		extReq.Header.Set("Authorization", e.authHeader)
	}

	// Send validation request with retries
	var lastErr error
	for i := 0; i <= e.retryCount; i++ {
		var resp *http.Response
		resp, lastErr = e.client.Do(extReq)
		if lastErr == nil {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return nil
			}

			// Read error response
			errorBody, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("validation failed: status=%d body=%s",
				resp.StatusCode, string(errorBody))
		}

		// Wait before retry
		if i < e.retryCount {
			time.Sleep(time.Second * time.Duration(i+1))
		}
	}

	return fmt.Errorf("validation failed after retries: %w", lastErr)
}

func (e *ExternalValidator) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	return nil
}
