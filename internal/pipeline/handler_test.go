package pipeline

import (
	"testing"

	dastModel "devsecops/internal/dast/model"
)

func TestCountDASTSeverities(t *testing.T) {
	counts := countDASTSeverities([]dastModel.Finding{
		{Severity: dastModel.SeverityHigh},
		{Severity: dastModel.SeverityHigh},
		{Severity: dastModel.SeverityMedium},
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
