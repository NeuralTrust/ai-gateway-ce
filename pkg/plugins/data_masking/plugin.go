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

type DataMaskingPlugin struct {
	logger     *logrus.Logger
	keywords   map[string]string         // map of keyword to mask value
	regexRules map[string]*regexp.Regexp // map of regex pattern to mask value
}

type Config struct {
	Rules               []Rule  `mapstructure:"rules"`
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`
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
	return []types.Stage{types.PreResponse}
}

func (p *DataMaskingPlugin) AllowedStages() []types.Stage {
	return []types.Stage{types.PreResponse}
}

type DataMaskingValidator struct{}

func (v *DataMaskingValidator) ValidateConfig(config types.PluginConfig) error {
	var cfg Config
	if err := mapstructure.Decode(config.Settings, &cfg); err != nil {
		return fmt.Errorf("failed to decode config: %v", err)
	}

	if len(cfg.Rules) == 0 {
		return fmt.Errorf("at least one masking rule must be specified")
	}

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

	// Get response content
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

	return &types.PluginResponse{
		StatusCode: 200,
		Message:    "Content masked successfully",
	}, nil
}
