package data_masking

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/NeuralTrust/TrustGate/pkg/pluginiface"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

const (
	PluginName          = "data_masking"
	DefaultMaskChar     = "*"
	SimilarityThreshold = 0.8
)

// PredefinedEntity represents a pre-defined entity type to mask
type PredefinedEntity string

const (
	CreditCard    PredefinedEntity = "credit_card"
	Email         PredefinedEntity = "email"
	PhoneNumber   PredefinedEntity = "phone_number"
	SSN           PredefinedEntity = "ssn"
	IPAddress     PredefinedEntity = "ip_address"
	BankAccount   PredefinedEntity = "bank_account"
	Password      PredefinedEntity = "password"
	APIKey        PredefinedEntity = "api_key"
	AccessToken   PredefinedEntity = "access_token"
	IBAN          PredefinedEntity = "iban"
	SwiftBIC      PredefinedEntity = "swift_bic"
	CryptoWallet  PredefinedEntity = "crypto_wallet"
	TaxID         PredefinedEntity = "tax_id"
	RoutingNumber PredefinedEntity = "routing_number"
)

// predefinedEntityPatterns maps entity types to their regex patterns
var predefinedEntityPatterns = map[PredefinedEntity]string{
	CreditCard:    `\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`,
	Email:         `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
	PhoneNumber:   `\b\+?[\d\s-]{10,}\b`,
	SSN:           `\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b`,
	IPAddress:     `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	BankAccount:   `\b\d{8,17}\b`,
	Password:      `(?i)password[\s]*[=:]\s*\S+`,
	APIKey:        `(?i)(api[_-]?key|access[_-]?key)[\s]*[=:]\s*\S+`,
	AccessToken:   `(?i)(access[_-]?token|bearer)[\s]*[=:]\s*\S+`,
	IBAN:          `\b[A-Z]{2}\d{2}[A-Z0-9]{4,34}\b`,
	SwiftBIC:      `\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`,
	CryptoWallet:  `\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|0x[a-fA-F0-9]{40}\b`,
	TaxID:         `\b\d{2}[-\s]?\d{7}\b`,
	RoutingNumber: `\b\d{9}\b`,
}

// defaultEntityMasks defines default masking for pre-defined entities
var defaultEntityMasks = map[PredefinedEntity]string{
	CreditCard:    "[MASKED_CC]",
	Email:         "[MASKED_EMAIL]",
	PhoneNumber:   "[MASKED_PHONE]",
	SSN:           "[MASKED_SSN]",
	IPAddress:     "[MASKED_IP]",
	BankAccount:   "[MASKED_ACCOUNT]",
	Password:      "[MASKED_PASSWORD]",
	APIKey:        "[MASKED_API_KEY]",
	AccessToken:   "[MASKED_TOKEN]",
	IBAN:          "[MASKED_IBAN]",
	SwiftBIC:      "[MASKED_BIC]",
	CryptoWallet:  "[MASKED_WALLET]",
	TaxID:         "[MASKED_TAX_ID]",
	RoutingNumber: "[MASKED_ROUTING]",
}

type DataMaskingPlugin struct {
	logger     *logrus.Logger
	keywords   map[string]string         // map of keyword to mask value
	regexRules map[string]*regexp.Regexp // map of regex pattern to mask value
}

type Config struct {
	Rules               []Rule         `mapstructure:"rules"`
	SimilarityThreshold float64        `mapstructure:"similarity_threshold"`
	PredefinedEntities  []EntityConfig `mapstructure:"predefined_entities"`
}

type EntityConfig struct {
	Entity      string `mapstructure:"entity"`       // Pre-defined entity type
	Enabled     bool   `mapstructure:"enabled"`      // Whether to enable this entity
	MaskWith    string `mapstructure:"mask_with"`    // Optional custom mask
	PreserveLen bool   `mapstructure:"preserve_len"` // Whether to preserve length
}

type Rule struct {
	Pattern     string `mapstructure:"pattern"`      // Keyword or regex pattern
	Type        string `mapstructure:"type"`         // "keyword" or "regex"
	MaskWith    string `mapstructure:"mask_with"`    // Character or string to mask with
	PreserveLen bool   `mapstructure:"preserve_len"` // Whether to preserve the length of masked content
}

// levenshteinDistance calculates the minimum number of single-character edits required to change one word into another
func levenshteinDistance(s1, s2 string) int {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(s1)][len(s2)]
}

// min returns the minimum of three integers
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// calculateSimilarity returns a similarity score between 0 and 1
func calculateSimilarity(s1, s2 string) float64 {
	distance := levenshteinDistance(s1, s2)
	maxLen := float64(max(len(s1), len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// findSimilarKeyword checks if any word in the text is similar to the keywords
func (p *DataMaskingPlugin) findSimilarKeyword(text string, threshold float64) (string, string, string, bool) {
	words := strings.Fields(text)
	for _, word := range words {
		for keyword, maskWith := range p.keywords {
			similarity := calculateSimilarity(word, keyword)
			if similarity >= threshold {
				return word, keyword, maskWith, true
			}
		}
	}
	return "", "", "", false
}

func NewDataMaskingPlugin(logger *logrus.Logger) pluginiface.Plugin {
	return &DataMaskingPlugin{
		logger:     logger,
		keywords:   make(map[string]string),
		regexRules: make(map[string]*regexp.Regexp),
	}
}

func (p *DataMaskingPlugin) Name() string {
	return PluginName
}

func (p *DataMaskingPlugin) Stages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PreResponse}
}

func (p *DataMaskingPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreRequest, types.PreResponse}
}

type DataMaskingValidator struct{}

func (v *DataMaskingValidator) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.Rules) == 0 && len(cfg.PredefinedEntities) == 0 {
		return fmt.Errorf("at least one rule or predefined entity must be specified")
	}

	// Validate custom rules
	for _, rule := range cfg.Rules {
		if rule.Type != "keyword" && rule.Type != "regex" {
			return fmt.Errorf("invalid rule type '%s': must be 'keyword' or 'regex'", rule.Type)
		}

		if rule.Type == "regex" {
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				return fmt.Errorf("invalid regex pattern '%s': %v", rule.Pattern, err)
			}
		}

		if rule.MaskWith == "" {
			return fmt.Errorf("mask_with value must be specified for each rule")
		}
	}

	// Validate predefined entities
	for _, entity := range cfg.PredefinedEntities {
		if _, exists := predefinedEntityPatterns[PredefinedEntity(entity.Entity)]; !exists {
			return fmt.Errorf("invalid predefined entity type: %s", entity.Entity)
		}
	}

	return nil
}

func (p *DataMaskingPlugin) maskContent(content string, pattern string, maskWith string, preserveLen bool) string {
	if preserveLen {
		mask := strings.Repeat(maskWith[0:1], len(content))
		return mask
	}
	return maskWith
}

func (p *DataMaskingPlugin) Execute(ctx context.Context, cfg types.PluginConfig, req *types.RequestContext, resp *types.ResponseContext) (*types.PluginResponse, error) {
	var config Config
	if err := mapstructure.Decode(cfg.Settings, &config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %v", err)
	}

	threshold := config.SimilarityThreshold
	if threshold == 0 {
		threshold = SimilarityThreshold
	}

	// Initialize rules
	p.keywords = make(map[string]string)
	p.regexRules = make(map[string]*regexp.Regexp)

	// Add custom rules
	for _, rule := range config.Rules {
		maskValue := rule.MaskWith
		if maskValue == "" {
			maskValue = DefaultMaskChar
		}

		if rule.Type == "keyword" {
			p.keywords[rule.Pattern] = maskValue
		} else if rule.Type == "regex" {
			regex, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("failed to compile regex pattern '%s': %v", rule.Pattern, err)
			}
			p.regexRules[maskValue] = regex
		}
	}

	// Add predefined entity rules
	for _, entity := range config.PredefinedEntities {
		if !entity.Enabled {
			continue
		}

		entityType := PredefinedEntity(entity.Entity)
		pattern, exists := predefinedEntityPatterns[entityType]
		if !exists {
			continue
		}

		maskValue := entity.MaskWith
		if maskValue == "" {
			maskValue = defaultEntityMasks[entityType]
		}

		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile predefined pattern for entity %s: %v", entity.Entity, err)
		}
		p.regexRules[maskValue] = regex
	}

	// Process request body if in PreRequest stage
	if req != nil && len(req.Body) > 0 {
		content := string(req.Body)
		maskedContent := content

		// Apply fuzzy keyword masking
		for {
			foundWord, keyword, maskWith, found := p.findSimilarKeyword(maskedContent, threshold)
			if !found {
				break
			}
			maskedContent = strings.ReplaceAll(maskedContent, foundWord, p.maskContent(foundWord, keyword, maskWith, true))
		}

		// Apply regex masking
		for maskWith, regex := range p.regexRules {
			maskedContent = regex.ReplaceAllStringFunc(maskedContent, func(match string) string {
				return p.maskContent(match, regex.String(), maskWith, true)
			})
		}

		// Update request with masked content
		req.Body = []byte(maskedContent)
	}

	// Process response body if in PreResponse stage
	if resp != nil && len(resp.Body) > 0 {
		content := string(resp.Body)
		maskedContent := content

		// Apply fuzzy keyword masking
		for {
			foundWord, keyword, maskWith, found := p.findSimilarKeyword(maskedContent, threshold)
			if !found {
				break
			}
			maskedContent = strings.ReplaceAll(maskedContent, foundWord, p.maskContent(foundWord, keyword, maskWith, true))
		}

		// Apply regex masking
		for maskWith, regex := range p.regexRules {
			maskedContent = regex.ReplaceAllStringFunc(maskedContent, func(match string) string {
				return p.maskContent(match, regex.String(), maskWith, true)
			})
		}

		// Update response with masked content
		resp.Body = []byte(maskedContent)
	}

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Content masked successfully",
	}, nil
}
