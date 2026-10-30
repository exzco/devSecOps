package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"devsecops/internal/sca/model"
	"devsecops/internal/sca/parser"
)

const (
	defaultOSVBatchURL = "https://api.osv.dev/v1/querybatch"
	defaultOSVVulnURL  = "https://api.osv.dev/v1/vulns"
	defaultBatchSize   = 100
)

type OSVClient struct {
	httpClient *http.Client
	cacheMu    sync.RWMutex
	vulnCache  map[string]*osvVulnDetail
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		vulnCache: make(map[string]*osvVulnDetail),
	}
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVulnDetail struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

type MatchedFinding struct {
	Dependency     parser.ParsedDependency
	VulnID         string
	Aliases        string
	Severity       string
	Title          string
	Summary        string
	Details        string
	FixedVersion   string
	ReferencesJSON string
}

// CheckDependencies scans a list of parsed dependencies against the OSV API
func (c *OSVClient) CheckDependencies(ctx context.Context, deps []parser.ParsedDependency) ([]MatchedFinding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	var findings []MatchedFinding

	// Process in batches of defaultBatchSize
	for i := 0; i < len(deps); i += defaultBatchSize {
		end := i + defaultBatchSize
		if end > len(deps) {
			end = len(deps)
		}
		chunk := deps[i:end]

		chunkFindings, err := c.queryBatch(ctx, chunk)
		if err != nil {
			log.Printf("[OSVClient] Warning: query batch failed (%d-%d): %v", i, end, err)
			continue
		}
		findings = append(findings, chunkFindings...)
	}

	return findings, nil
}

func (c *OSVClient) queryBatch(ctx context.Context, deps []parser.ParsedDependency) ([]MatchedFinding, error) {
	reqBody := osvBatchRequest{
		Queries: make([]osvQuery, len(deps)),
	}
	for i, d := range deps {
		ver := d.Version
		if ver == "*" {
			ver = ""
		}
		reqBody.Queries[i] = osvQuery{
			Package: osvPackage{
				Name:      d.Name,
				Ecosystem: d.Ecosystem,
			},
			Version: ver,
		}
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, defaultOSVBatchURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OSV API HTTP %d: %s", resp.StatusCode, string(b))
	}

	var batchResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, err
	}

	var findings []MatchedFinding

	for i, res := range batchResp.Results {
		if i >= len(deps) || len(res.Vulns) == 0 {
			continue
		}
		dep := deps[i]

		for _, v := range res.Vulns {
			detail, err := c.getVulnDetail(ctx, v.ID)
			if err != nil {
				log.Printf("[OSVClient] Warning: fetch vuln detail %s: %v", v.ID, err)
				findings = append(findings, MatchedFinding{
					Dependency: dep,
					VulnID:     v.ID,
					Severity:   model.SeverityMedium,
					Title:      v.ID,
					Summary:    "Vulnerability identified in " + dep.Name,
				})
				continue
			}

			severity := normalizeSeverity(detail)
			fixedVer := extractFixedVersion(detail, dep.Name)
			aliases := strings.Join(detail.Aliases, ", ")
			refsJSON, _ := json.Marshal(detail.References)

			title := detail.Summary
			if title == "" {
				title = detail.ID
			}

			findings = append(findings, MatchedFinding{
				Dependency:     dep,
				VulnID:         detail.ID,
				Aliases:        aliases,
				Severity:       severity,
				Title:          title,
				Summary:        detail.Summary,
				Details:        detail.Details,
				FixedVersion:   fixedVer,
				ReferencesJSON: string(refsJSON),
			})
		}
	}

	return findings, nil
}

func (c *OSVClient) getVulnDetail(ctx context.Context, vulnID string) (*osvVulnDetail, error) {
	c.cacheMu.RLock()
	cached, ok := c.vulnCache[vulnID]
	c.cacheMu.RUnlock()
	if ok && cached != nil {
		return cached, nil
	}

	url := fmt.Sprintf("%s/%s", defaultOSVVulnURL, vulnID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln detail HTTP %d", resp.StatusCode)
	}

	var detail osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return nil, err
	}

	c.cacheMu.Lock()
	c.vulnCache[vulnID] = &detail
	c.cacheMu.Unlock()

	return &detail, nil
}

func normalizeSeverity(v *osvVulnDetail) string {
	// 1. Check CVSS scores
	for _, s := range v.Severity {
		if strings.HasPrefix(s.Type, "CVSS") {
			// Try score parsing: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" or numerical
			if num, err := strconv.ParseFloat(s.Score, 64); err == nil {
				return scoreToSeverity(num)
			}
			// Parse vector metrics
			if strings.Contains(s.Score, "/C:H/I:H/A:H") || strings.Contains(s.Score, "/C:H/I:H") {
				return model.SeverityHigh
			}
		}
	}

	// 2. Check DatabaseSpecific severity
	raw := strings.ToUpper(strings.TrimSpace(v.DatabaseSpecific.Severity))
	switch raw {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MODERATE", "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	}

	// 3. Check affected package database specific
	for _, aff := range v.Affected {
		aRaw := strings.ToUpper(strings.TrimSpace(aff.DatabaseSpecific.Severity))
		switch aRaw {
		case "CRITICAL":
			return model.SeverityCritical
		case "HIGH":
			return model.SeverityHigh
		case "MODERATE", "MEDIUM":
			return model.SeverityMedium
		case "LOW":
			return model.SeverityLow
		}
	}

	return model.SeverityMedium
}

func scoreToSeverity(score float64) string {
	if score >= 9.0 {
		return model.SeverityCritical
	}
	if score >= 7.0 {
		return model.SeverityHigh
	}
	if score >= 4.0 {
		return model.SeverityMedium
	}
	if score > 0 {
		return model.SeverityLow
	}
	return model.SeverityInfo
}

func extractFixedVersion(detail *osvVulnDetail, pkgName string) string {
	for _, aff := range detail.Affected {
		if aff.Package.Name == "" || strings.EqualFold(aff.Package.Name, pkgName) {
			for _, r := range aff.Ranges {
				for _, ev := range r.Events {
					if ev.Fixed != "" {
						return ev.Fixed
					}
				}
			}
		}
	}
	return ""
}
