package engine

import (
	"bufio"
	"context"
	"strings"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"devsecops/pkg/logger"
)

type Finding struct {
	TemplateID string   `json:"templateId"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Matched    string   `json:"matched"`
	Tags       []string `json:"tags"`
	Response   string   `json:"response,omitempty"`
}

func ScanWithTags(ctx context.Context, target string, tags []string, pocDir string) ([]Finding, error) {
	logger.DAST("PocScan", "scanning target=%s tags=%v pocDir=%s", target, tags, pocDir)

	if len(tags) == 0 {
		tags = []string{"exposure", "misconfig", "config"}
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithCatalog(disk.NewCatalog(pocDir)),
		nuclei.DisableUpdateCheck(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: []string{pocDir},
		}),
	)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	if err := engine.LoadAllTemplates(); err != nil {
		if strings.Contains(err.Error(), "No templates available") {
			logger.DAST("PocScan", "no templates found matching tags %v in %s", tags, pocDir)
			return nil, nil
		}
		return nil, err
	}

	reader := bufio.NewReader(strings.NewReader(target))
	engine.LoadTargetsFromReader(reader, false)

	var findings []Finding
	err = engine.ExecuteCallbackWithCtx(ctx, func(ev *output.ResultEvent) {
		if ev == nil || !ev.MatcherStatus {
			return
		}
		response := ev.Response
		if len(response) > 10240 {
			response = response[:10240]
		}
		findings = append(findings, Finding{
			TemplateID: ev.TemplateID,
			Name:       ev.Info.Name,
			Severity:   ev.Info.SeverityHolder.Severity.String(),
			Matched:    ev.Matched,
			Tags:       tags,
			Response:   response,
		})
	})
	if err != nil {
		if strings.Contains(err.Error(), "No templates available") {
			logger.DAST("PocScan", "no templates found matching tags %v", tags)
			return findings, nil
		}
		return findings, err
	}

	logger.DAST("PocScan", "target=%s found %d findings", target, len(findings))
	return findings, nil
}
