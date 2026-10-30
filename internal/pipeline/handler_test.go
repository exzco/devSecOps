package pipeline

import (
	"testing"

	"devsecops/internal/model"
)

func TestCountDASTSeverities(t *testing.T) {
	counts := countDASTSeverities([]model.Finding{
		{BaseVulnerability: model.BaseVulnerability{Severity: model.SeverityHigh}},
		{BaseVulnerability: model.BaseVulnerability{Severity: model.SeverityHigh}},
		{BaseVulnerability: model.BaseVulnerability{Severity: model.SeverityMedium}},
	})
	if counts["high"] != 2 || counts["medium"] != 1 {
		t.Fatalf("unexpected counts: %#v", counts)
	}
}

func TestTerminalStatuses(t *testing.T) {
	for _, status := range []string{"success", "failed", "canceled", "timeout"} {
		if !isSASTTerminal(status) {
			t.Fatalf("%s should be terminal for SAST", status)
		}
	}
	for _, status := range []string{"completed", "failed", "cancelled"} {
		if !isDASTTerminal(status) {
			t.Fatalf("%s should be terminal for DAST", status)
		}
	}
	if isDASTTerminal("running") {
		t.Fatal("running DAST scan must not be terminal")
	}
}
