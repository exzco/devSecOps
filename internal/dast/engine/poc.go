package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/chainreactors/neutron/protocols"
	"github.com/chainreactors/neutron/templates"

	"devsecops/internal/model"
)

const DefaultPOCIndexFile = "poc_index.json"

type RuleIndex struct {
	mu    sync.RWMutex
	specs []model.CheckSpec
}

func NewRuleIndex(pocDir, indexFile string) *RuleIndex {
	if pocDir == "" {
		pocDir = "./data/pocs"
	}
	if indexFile == "" {
		indexFile = DefaultPOCIndexFile
	}

	idx := &RuleIndex{}

	indexPath := filepath.Join(pocDir, indexFile)
	if data, err := os.ReadFile(indexPath); err == nil {
		var rawSpecs []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Severity    string   `json:"severity"`
			Tags        []string `json:"tags"`
			FilePath    string   `json:"file_path"`
		}
		if json.Unmarshal(data, &rawSpecs) == nil {
			for _, r := range rawSpecs {
				sev := model.SeverityMedium
				switch strings.ToUpper(r.Severity) {
				case "CRITICAL":
					sev = model.SeverityCritical
				case "HIGH":
					sev = model.SeverityHigh
				case "LOW":
					sev = model.SeverityLow
				case "INFO":
					sev = model.SeverityInfo
				}

				spec := model.CheckSpec{
					ID:       r.ID,
					Name:     r.Name,
					FilePath: filepath.Join(pocDir, r.FilePath),
					Severity: sev,
					Tags:     r.Tags,
				}
				idx.AddSpec(spec)
			}
		}
	}

	return idx
}

func (idx *RuleIndex) AddSpec(spec model.CheckSpec) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.specs = append(idx.specs, spec)
}

func (idx *RuleIndex) SelectChecks(pol *model.Policy) []model.CheckSpec {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	var selected []model.CheckSpec
	for _, spec := range idx.specs {
		if passPolicy(spec, pol) {
			selected = append(selected, spec)
		}
	}
	return selected
}

func passPolicy(spec model.CheckSpec, pol *model.Policy) bool {
	if pol == nil {
		return true
	}
	for _, dt := range pol.DeniedTags {
		for _, st := range spec.Tags {
			if strings.EqualFold(dt, st) {
				return false
			}
		}
	}
	return true
}

func ExecuteChecks(ctx context.Context, specs []model.CheckSpec, scanRunID, targetURL string) ([]model.Finding, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	var findings []model.Finding

	for _, spec := range specs {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		pocPath := spec.FilePath
		yamlBytes, err := os.ReadFile(pocPath)
		if err != nil {
			continue
		}

		tmpl, err := templates.Load(yamlBytes)
		if err != nil {
			continue
		}

		_ = tmpl.Compile(&protocols.ExecuterOptions{
			Options: &protocols.Options{},
		})

		res, err := tmpl.Execute(targetURL, nil)
		if err == nil && res != nil && res.Matched {
			finding := model.Finding{
				BaseVulnerability: model.BaseVulnerability{
					Title:       spec.Name,
					Description: fmt.Sprintf("Neutron POC %s matched on %s", spec.ID, targetURL),
					Severity:    spec.Severity,
				},
				ID:        model.NewUUID(),
				ScanRunID: scanRunID,
				StableKey: model.GenerateStableFindingKey(targetURL, targetURL, spec.ID, "", ""),
				CheckID:   spec.ID,
				MatchedAt: targetURL,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
