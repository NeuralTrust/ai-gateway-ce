package security_validator

import (
	"context"
	"fmt"
	"strings"

	"ai-gateway/internal/plugins"

	"github.com/sirupsen/logrus"
)

type SecurityValidator struct {
	requiredHeaders []string
	blockedIPs      []string
	fields          []string // Fields to validate
	logger          *logrus.Logger
}

type Config struct {
	RequiredHeaders []string `json:"required_headers"`
	BlockedIPs      []string `json:"blocked_ips"`
	Fields          []string `json:"fields"` // Fields to validate
}

func NewSecurityValidator(config Config, logger *logrus.Logger) *SecurityValidator {
	return &SecurityValidator{
		requiredHeaders: config.RequiredHeaders,
		blockedIPs:      config.BlockedIPs,
		fields:          config.Fields,
		logger:          logger,
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
	v.logger.WithFields(logrus.Fields{
		"plugin":           "security_validator",
		"tenant_id":        reqCtx.TenantID,
		"path":             reqCtx.OriginalRequest.URL.Path,
		"required_headers": v.requiredHeaders,
		"client_ip":        reqCtx.OriginalRequest.RemoteAddr,
	}).Debug("Starting security validation")

	// Check required headers
	for _, header := range v.requiredHeaders {
		if reqCtx.OriginalRequest.Header.Get(header) == "" {
			v.logger.WithFields(logrus.Fields{
				"plugin": "security_validator",
				"header": header,
			}).Warn("Missing required header")
			return fmt.Errorf("missing required header: %s", header)
		}
	}

	// Check IP
	ip := strings.Split(reqCtx.OriginalRequest.RemoteAddr, ":")[0]
	for _, blocked := range v.blockedIPs {
		if ip == blocked {
			v.logger.WithFields(logrus.Fields{
				"plugin": "security_validator",
				"ip":     ip,
			}).Warn("Blocked IP attempted access")
			return fmt.Errorf("IP %s is blocked", ip)
		}
	}

	v.logger.WithFields(logrus.Fields{
		"plugin":    "security_validator",
		"tenant_id": reqCtx.TenantID,
	}).Debug("Security validation successful")

	return nil
}

func (v *SecurityValidator) ProcessResponse(ctx context.Context, respCtx *plugins.ResponseContext) error {
	return nil
}
