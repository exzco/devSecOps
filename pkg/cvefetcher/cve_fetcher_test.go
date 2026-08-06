package cvefetcher

import (
	"context"
	"testing"
	"time"
)

func TestLiveCVEFetching(t *testing.T) {
	fetcher := NewCVEFetcher(15 * time.Second)
	ctx := context.Background()

	// Test 1: Fetch live GitHub Security Advisories for "php"
	cves, err := fetcher.FetchRecentCVEs(ctx, "php", 2024)
	if err != nil {
		t.Fatalf("FetchRecentCVEs failed: %v", err)
	}

	t.Logf("Fetched %d live online CVE entries for 'php' in 2024", len(cves))
	for i, cve := range cves {
		if i >= 5 {
			break
		}
		t.Logf("[%d] ID: %s | Component: %s | Severity: %s | Summary: %s", i+1, cve.ID, cve.Component, cve.Severity, cve.Summary)
	}
}
