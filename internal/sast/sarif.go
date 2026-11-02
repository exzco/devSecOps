package sast

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"devsecops/internal/model"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool struct {
		Driver struct {
			Rules []SARIFRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results   []SARIFResult `json:"results"`
	Artifacts []struct {
		Location struct {
			URI string `json:"uri"`
		} `json:"location"`
	} `json:"artifacts"`
	Extensions []struct {
		Rules []SARIFRule `json:"rules"`
	} `json:"extensions"`
}

type SARIFRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	FullDescription  SARIFMessage `json:"fullDescription"`
	DefaultConfig    struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		Severity        string `json:"security-severity"`
		Problem         struct {
			Severity string `json:"severity"`
		} `json:"problem"`
		ProblemSeverity string `json:"problem.severity"`
	} `json:"properties"`
}

type SARIFMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type SARIFResult struct {
	RuleID string `json:"ruleId"`
	Rule   *struct {
		ID string `json:"id"`
	}
	Message             SARIFMessage    `json:"message"`
	Locations           []SARIFLocation `json:"locations"`
	RelatedLocations    []SARIFLocation `json:"relatedLocations"`
	CodeFlows           []SARIFCodeFlow `json:"codeFlows"`
	PartialFingerprints map[string]string
	Level               string `json:"level"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	Message          *SARIFMessage         `json:"message,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation struct {
		URI   string `json:"uri"`
		Index int    `json:"index"`
	} `json:"artifactLocation"`
	Region        SARIFRegion  `json:"region"`
	ContextRegion *SARIFRegion `json:"contextRegion,omitempty"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
	Snippet   *struct {
		Text string `json:"text"`
	} `json:"snippet,omitempty"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []struct {
		Location SARIFLocation `json:"location"`
		Message  *SARIFMessage `json:"message,omitempty"`
	} `json:"locations"`
}

func ParseSARIF(filePath string) ([]Vulnerability, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read SARIF file: %w", err)
	}
	return ParseSARIFData(data)
}

func ParseSARIFData(data []byte) ([]Vulnerability, error) {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse SARIF JSON: %w", err)
	}

	var vulnerabilities []Vulnerability
	for _, run := range report.Runs {
		rules := buildRuleMap(run)
		artifacts := make(map[int]string, len(run.Artifacts))
		for index, artifact := range run.Artifacts {
			if artifact.Location.URI != "" {
				artifacts[index] = artifact.Location.URI
			}
		}

		for _, result := range run.Results {
			ruleID := result.RuleID
			if ruleID == "" && result.Rule != nil {
				ruleID = result.Rule.ID
			}
			if ruleID == "" {
				ruleID = "unknown-rule"
			}
			vulnerability := Vulnerability{
				BaseVulnerability: model.BaseVulnerability{
					RuleID:  ruleID,
					Message: firstNonEmpty(result.Message.Text, result.Message.Markdown),
				},
			}
			if rule, ok := rules[ruleID]; ok {
				vulnerability.RuleName = firstNonEmpty(
					rule.ShortDescription.Text,
					rule.Name,
					rule.FullDescription.Text,
					rule.ID,
				)
				vulnerability.Severity = ruleSeverity(rule, result.Level)
			} else {
				vulnerability.Severity = levelSeverity(result.Level)
			}
			if vulnerability.RuleName == "" {
				vulnerability.RuleName = ruleID
			}

			if location, ok := primaryLocation(result); ok {
				vulnerability.FilePath = artifactURI(
					location.ArtifactLocation.URI,
					location.ArtifactLocation.Index,
					artifacts,
				)
				vulnerability.StartLine = location.Region.StartLine
				vulnerability.EndLine = location.Region.EndLine
				if vulnerability.EndLine == 0 {
					vulnerability.EndLine = vulnerability.StartLine
				}
				if location.ContextRegion != nil && location.ContextRegion.Snippet != nil {
					vulnerability.CodeSnippet = location.ContextRegion.Snippet.Text
				} else if location.Region.Snippet != nil {
					vulnerability.CodeSnippet = location.Region.Snippet.Text
				}
			}
			vulnerability.FilePath = normalizePath(vulnerability.FilePath)
			vulnerability.DataFlow = dataFlow(result.CodeFlows, artifacts)

			base := fmt.Sprintf("%s:%s:%d:%d",
				vulnerability.RuleID,
				vulnerability.FilePath,
				vulnerability.StartLine,
				vulnerability.EndLine,
			)
			hash := sha1.Sum([]byte(base))
			vulnerability.Fingerprint = fmt.Sprintf("%x", hash)
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return deduplicate(vulnerabilities), nil
}

func deduplicate(vulnerabilities []Vulnerability) []Vulnerability {
	indexes := make(map[string]int, len(vulnerabilities))
	result := make([]Vulnerability, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		k := vulnerability.Fingerprint
		if index, exists := indexes[k]; exists {
			result[index].DataFlow = append(result[index].DataFlow, vulnerability.DataFlow...)
			if result[index].CodeSnippet == "" && vulnerability.CodeSnippet != "" {
				result[index].CodeSnippet = vulnerability.CodeSnippet
			}
			continue
		}
		indexes[k] = len(result)
		result = append(result, vulnerability)
	}
	return result
}

func buildRuleMap(run SARIFRun) map[string]SARIFRule {
	rules := make(map[string]SARIFRule)
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	for _, extension := range run.Extensions {
		for _, rule := range extension.Rules {
			if _, exists := rules[rule.ID]; !exists {
				rules[rule.ID] = rule
			}
		}
	}
	return rules
}

func primaryLocation(result SARIFResult) (SARIFPhysicalLocation, bool) {
	if len(result.Locations) > 0 {
		return result.Locations[0].PhysicalLocation, true
	}
	if len(result.RelatedLocations) > 0 {
		return result.RelatedLocations[0].PhysicalLocation, true
	}
	return SARIFPhysicalLocation{}, false
}

func artifactURI(uri string, index int, artifacts map[int]string) string {
	if uri != "" {
		return uri
	}
	return artifacts[index]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func ruleSeverity(rule SARIFRule, level string) string {
	for _, value := range []string{
		rule.Properties.Severity,
		rule.Properties.ProblemSeverity,
		rule.Properties.Problem.Severity,
		rule.DefaultConfig.Level,
	} {
		if value != "" {
			if score, err := strconv.ParseFloat(value, 64); err == nil {
				switch {
				case score >= 9:
					return "critical"
				case score >= 7:
					return "high"
				case score >= 4:
					return "medium"
				case score >= 0.1:
					return "low"
				default:
					return "info"
				}
			}
			return levelSeverity(value)
		}
	}
	return levelSeverity(level)
}

func levelSeverity(level string) string {
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

func dataFlow(codeFlows []SARIFCodeFlow, artifacts map[int]string) [][]model.FlowStep {
	var paths [][]model.FlowStep
	for _, codeFlow := range codeFlows {
		for _, thread := range codeFlow.ThreadFlows {
			var steps []model.FlowStep
			for _, item := range thread.Locations {
				location := item.Location
				step := model.FlowStep{
					FilePath: normalizePath(artifactURI(
						location.PhysicalLocation.ArtifactLocation.URI,
						location.PhysicalLocation.ArtifactLocation.Index,
						artifacts,
					)),
					StartLine: location.PhysicalLocation.Region.StartLine,
					EndLine:   location.PhysicalLocation.Region.EndLine,
				}
				if step.EndLine == 0 {
					step.EndLine = step.StartLine
				}
				if location.Message != nil {
					step.Message = firstNonEmpty(location.Message.Text, location.Message.Markdown)
				} else if item.Message != nil {
					step.Message = firstNonEmpty(item.Message.Text, item.Message.Markdown)
				}
				if location.PhysicalLocation.Region.Snippet != nil {
					step.Snippet = location.PhysicalLocation.Region.Snippet.Text
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

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.TrimPrefix(path, "file://")
	path = strings.TrimPrefix(path, "file:///")
	if path == "" {
		return ""
	}
	return filepath.ToSlash(path)
}
