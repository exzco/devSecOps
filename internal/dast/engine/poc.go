package engine

import (
	"bufio"
	"context"
	"strings"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"devsecops/internal/dast/logger"
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
	logger.Printf("[poc] scanning target=%s tags=%v pocDir=%s\n", target, tags, pocDir)

	if len(tags) == 0 {
		tags = []string{"exposure", "misconfig", "config"}
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithCatalog(disk.NewCatalog(pocDir)),
		nuclei.DisableUpdateCheck(),
	)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

	if err := engine.LoadAllTemplates(); err != nil {
		if strings.Contains(err.Error(), "No templates available") {
			logger.Printf("[poc] no templates found matching tags %v in %s\n", tags, pocDir)
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
		resp := ev.Response
		if len(resp) > 10240 {
			resp = resp[:10240]
		}
		findings = append(findings, Finding{
			TemplateID: ev.TemplateID,
			Name:       ev.Info.Name,
			Severity:   ev.Info.SeverityHolder.Severity.String(),
			Matched:    ev.Matched,
			Tags:       tags,
			Response:   resp,
		})
	})

	if err != nil {
		if strings.Contains(err.Error(), "No templates available") {
			logger.Printf("[poc] no templates found matching tags %v\n", tags)
			return findings, nil
		}
		return findings, err
	}

	logger.Printf("[poc] target=%s found %d findings\n", target, len(findings))
	return findings, nil
}
