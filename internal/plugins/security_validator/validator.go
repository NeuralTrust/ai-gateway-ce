package security_validator

import (
	"context"
	"fmt"
	"strings"

	"ai-gateway/internal/plugins"
)

type SecurityValidator struct {
	requiredHeaders []string
	blockedIPs      []string
	fields          []string // Fields to validate
}

type Config struct {
	RequiredHeaders []string `json:"required_headers"`
	BlockedIPs      []string `json:"blocked_ips"`
	Fields          []string `json:"fields"` // Fields to validate
}

func NewSecurityValidator(config Config) *SecurityValidator {
	return &SecurityValidator{
		requiredHeaders: config.RequiredHeaders,
		blockedIPs:      config.BlockedIPs,
		fields:          config.Fields,
	}
}

func (v *SecurityValidator) Name() string {
	return "security_validator"
}

func (v *SecurityValidator) Priority() int {
	return 1
}

func (v *SecurityValidator) Stage() plugins.ExecutionStage {
	return plugins.PreRequest
}

func (v *SecurityValidator) Parallel() bool {
	return true
}

func (v *SecurityValidator) ProcessRequest(ctx context.Context, reqCtx *plugins.RequestContext) error {
	// Check required headers
	for _, header := range v.requiredHeaders {
		if reqCtx.OriginalRequest.Header.Get(header) == "" {
			return fmt.Errorf("missing required header: %s", header)
		}
	}

	// Check IP
	ip := strings.Split(reqCtx.OriginalRequest.RemoteAddr, ":")[0]
	for _, blocked := range v.blockedIPs {
		if ip == blocked {
			return fmt.Errorf("IP %s is blocked", ip)
		}
	}

	// Validate specific fields if configured
	if len(v.fields) > 0 {
		for _, field := range v.fields {
			if _, exists := reqCtx.RequestBody[field]; !exists {
				return fmt.Errorf("required field missing: %s", field)
			}
		}
	}

	return nil
}

func (v *SecurityValidator) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	return nil
}
