package model

import "testing"

func TestQueueKeysUseSinglePrefix(t *testing.T) {
	cases := map[string]string{
		"status":   StatusKey("tenant-a", "scan-1"),
		"results":  ResultsKey("tenant-a", "scan-1"),
		"findings": FindingsKey("tenant-a", "scan-1"),
		"assets":   AssetsKey("tenant-a", "scan-1"),
		"targets":  TargetsKey("tenant-a", "scan-1"),
	}
	want := map[string]string{
		"status":   "tenant-a:status:scan-1",
		"results":  "tenant-a:results:scan-1",
		"findings": "tenant-a:findings:scan-1",
		"assets":   "tenant-a:assets:scan-1",
		"targets":  "tenant-a:targets:scan-1",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Fatalf("%s key = %q, want %q", name, got, want[name])
		}
	}
	if AllTasksKey("tenant-a") != "tenant-a:all_tasks" {
		t.Fatalf("unexpected all tasks key: %q", AllTasksKey("tenant-a"))
	}
}
