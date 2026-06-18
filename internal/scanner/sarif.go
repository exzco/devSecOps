package scanner

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool       SARIFTool       `json:"tool"`
	Results    []SARIFResult   `json:"results"`
	Artifacts  []SARIFArtifact `json:"artifacts"`
	Extensions []SARIFDriver   `json:"extensions"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name  string      `json:"name"`
	Rules []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription SARIFMessage        `json:"shortDescription"`
	FullDescription  SARIFMessage        `json:"fullDescription"`
	DefaultConfig    SARIFDefaultConfig  `json:"defaultConfiguration"`
	Properties       SARIFRuleProperties `json:"properties"`
}

type SARIFDefaultConfig struct {
	Level string `json:"level"`
}

type SARIFRuleProperties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"security-severity"`
	Problem  struct {
		Severity string `json:"severity"`
	} `json:"problem"`
	ProblemSeverity string `json:"problem.severity"`
}

type SARIFMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type SARIFResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Rule                *SARIFRuleRef     `json:"rule,omitempty"`
	Message             SARIFMessage      `json:"message"`
	Locations           []SARIFLocation   `json:"locations"`
	RelatedLocations    []SARIFLocation   `json:"relatedLocations"`
	CodeFlows           []SARIFCodeFlow   `json:"codeFlows"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Level               string            `json:"level"`
}

type SARIFRuleRef struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	Message          *SARIFMessage         `json:"message,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
	ContextRegion    *SARIFRegion          `json:"contextRegion,omitempty"`
}

type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
	Index     int    `json:"index"`
}

type SARIFRegion struct {
	StartLine   int           `json:"startLine"`
	StartColumn int           `json:"startColumn"`
	EndLine     int           `json:"endLine"`
	EndColumn   int           `json:"endColumn"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
	Message  *SARIFMessage `json:"message,omitempty"`
}

type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

type ParsedVulnerability struct {
	RuleID      string       `json:"rule_id"`
	RuleName    string       `json:"rule_name"`
	Severity    string       `json:"severity"`
	FilePath    string       `json:"file_path"`
	StartLine   int          `json:"start_line"`
	EndLine     int          `json:"end_line"`
	CodeSnippet string       `json:"code_snippet"`
	Message     string       `json:"message"`
	DataFlow    [][]FlowStep `json:"data_flow"`
	Fingerprint string       `json:"fingerprint"`
}

type FlowStep struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Message   string `json:"message"`
	Snippet   string `json:"snippet"`
}

func ParseSARIF(filePath string) ([]ParsedVulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF file: %w", err)
	}

	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF JSON: %w", err)
	}

	var vulns []ParsedVulnerability

	for _, run := range report.Runs {
		ruleMap := buildRuleMap(run)
		artifactMap := buildArtifactMap(run.Artifacts)

		for _, result := range run.Results {
			ruleID := resolveRuleID(result)
			msg := firstNonEmpty(result.Message.Text, result.Message.Markdown)

			vuln := ParsedVulnerability{
				RuleID:  ruleID,
				Message: msg,
			}

			if rule, ok := ruleMap[ruleID]; ok {
				vuln.RuleName = firstNonEmpty(
					rule.ShortDescription.Text,
					rule.Name,
					rule.FullDescription.Text,
					rule.ID,
				)
				vuln.Severity = mapSeverity(rule, result.Level)
			} else {
				vuln.Severity = mapLevelToSeverity(result.Level)
			}
			if vuln.RuleName == "" {
				vuln.RuleName = vuln.RuleID
			}

			if loc, ok := pickPrimaryLocation(result); ok {
				vuln.FilePath = resolveArtifactURI(loc.ArtifactLocation, artifactMap)
				vuln.StartLine = loc.Region.StartLine
				vuln.EndLine = loc.Region.EndLine
				if vuln.EndLine == 0 {
					vuln.EndLine = vuln.StartLine
				}
				if loc.ContextRegion != nil && loc.ContextRegion.Snippet != nil {
					vuln.CodeSnippet = loc.ContextRegion.Snippet.Text
				} else if loc.Region.Snippet != nil {
					vuln.CodeSnippet = loc.Region.Snippet.Text
				}
			}
			vuln.FilePath = normalizePath(vuln.FilePath)

			vuln.DataFlow = extractDataFlow(result.CodeFlows, artifactMap)

			if fp, ok := result.PartialFingerprints["primaryLocationLineHash"]; ok {
				vuln.Fingerprint = fp
			} else {
				base := fmt.Sprintf("%s|%s|%d|%d|%s", vuln.RuleID, vuln.FilePath, vuln.StartLine, vuln.EndLine, vuln.Message)
				h := sha1.Sum([]byte(base))
				vuln.Fingerprint = fmt.Sprintf("%x", h)
			}

			vulns = append(vulns, vuln)
		}
	}

	return vulns, nil
}

func buildRuleMap(run SARIFRun) map[string]SARIFRule {
	total := len(run.Tool.Driver.Rules)
	for _, ext := range run.Extensions {
		total += len(ext.Rules)
	}

	m := make(map[string]SARIFRule, total)
	for _, r := range run.Tool.Driver.Rules {
		m[r.ID] = r
	}
	for _, ext := range run.Extensions {
		for _, r := range ext.Rules {
			if _, exists := m[r.ID]; !exists {
				m[r.ID] = r
			}
		}
	}
	return m
}

func buildArtifactMap(artifacts []SARIFArtifact) map[int]string {
	m := make(map[int]string, len(artifacts))
	for i, a := range artifacts {
		if a.Location.URI != "" {
			m[i] = a.Location.URI
		}
	}
	return m
}

func resolveRuleID(result SARIFResult) string {
	if result.RuleID != "" {
		return result.RuleID
	}
	if result.Rule != nil && result.Rule.ID != "" {
		return result.Rule.ID
	}
	return "unknown-rule"
}

func pickPrimaryLocation(result SARIFResult) (SARIFPhysicalLocation, bool) {
	if len(result.Locations) > 0 {
		return result.Locations[0].PhysicalLocation, true
	}
	if len(result.RelatedLocations) > 0 {
		return result.RelatedLocations[0].PhysicalLocation, true
	}
	return SARIFPhysicalLocation{}, false
}

func resolveArtifactURI(loc SARIFArtifactLocation, artifacts map[int]string) string {
	if loc.URI != "" {
		return loc.URI
	}
	if uri, ok := artifacts[loc.Index]; ok {
		return uri
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func mapSeverity(rule SARIFRule, level string) string {
	if rule.Properties.Severity != "" {
		return securityScoreToSeverity(rule.Properties.Severity)
	}
	if rule.Properties.ProblemSeverity != "" {
		return mapLevelToSeverity(rule.Properties.ProblemSeverity)
	}
	if rule.Properties.Problem.Severity != "" {
		return mapLevelToSeverity(rule.Properties.Problem.Severity)
	}
	if rule.DefaultConfig.Level != "" {
		return mapLevelToSeverity(rule.DefaultConfig.Level)
	}
	return mapLevelToSeverity(level)
}

func securityScoreToSeverity(score string) string {
	s, err := strconv.ParseFloat(strings.TrimSpace(score), 64)
	if err != nil {
		return "info"
	}
	switch {
	case s >= 9.0:
		return "critical"
	case s >= 7.0:
		return "high"
	case s >= 4.0:
		return "medium"
	case s >= 0.1:
		return "low"
	default:
		return "info"
	}
}

func mapLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "info"
	}
}

func extractDataFlow(codeFlows []SARIFCodeFlow, artifacts map[int]string) [][]FlowStep {
	var paths [][]FlowStep
	for _, cf := range codeFlows {
		for _, tf := range cf.ThreadFlows {
			var steps []FlowStep
			for _, loc := range tf.Locations {
				step := FlowStep{
					FilePath:  normalizePath(resolveArtifactURI(loc.Location.PhysicalLocation.ArtifactLocation, artifacts)),
					StartLine: loc.Location.PhysicalLocation.Region.StartLine,
					EndLine:   loc.Location.PhysicalLocation.Region.EndLine,
				}
				if step.EndLine == 0 {
					step.EndLine = step.StartLine
				}
				if loc.Location.Message != nil {
					step.Message = firstNonEmpty(loc.Location.Message.Text, loc.Location.Message.Markdown)
				} else if loc.Message != nil {
					step.Message = firstNonEmpty(loc.Message.Text, loc.Message.Markdown)
				}
				if loc.Location.PhysicalLocation.Region.Snippet != nil {
					step.Snippet = loc.Location.PhysicalLocation.Region.Snippet.Text
				}
				steps = append(steps, step)
			}
			if len(steps) > 0 {
				paths = append(paths, steps)
			}
		}
	}
	return paths
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "file://")
	p = strings.TrimPrefix(p, "file:///")
	if p == "" {
		return p
	}
	return filepath.ToSlash(p)
}
