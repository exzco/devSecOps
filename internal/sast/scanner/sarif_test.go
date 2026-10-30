package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSARIFMinimalReport(t *testing.T) {
	report := `{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"rules": [{
	      "id": "go/sql-injection",
	      "name": "SQL injection",
	      "shortDescription": {"text": "SQL injection"},
	      "properties": {"security-severity": "8.8"}
	    }]}},
	    "artifacts": [{"location": {"uri": "src/main.go"}}],
	    "results": [{
	      "ruleId": "go/sql-injection",
	      "message": {"text": "tainted query"},
	      "locations": [{
	        "physicalLocation": {
	          "artifactLocation": {"index": 0},
	          "region": {"startLine": 10, "endLine": 12}
	        }
	      }]
	    }]
	  }]
	}`
	path := filepath.Join(t.TempDir(), "result.sarif")
	if err := os.WriteFile(path, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}

	vulnerabilities, err := ParseSARIF(path)
	if err != nil {
		t.Fatalf("ParseSARIF: %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("len = %d, want 1", len(vulnerabilities))
	}
	vulnerability := vulnerabilities[0]
	if vulnerability.RuleID != "go/sql-injection" ||
		vulnerability.Severity != "high" ||
		vulnerability.FilePath != "src/main.go" ||
		vulnerability.StartLine != 10 ||
		vulnerability.EndLine != 12 ||
		vulnerability.Fingerprint == "" {
		t.Fatalf("unexpected vulnerability: %#v", vulnerability)
	}
}
