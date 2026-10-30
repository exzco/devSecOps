package scheduler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"devsecops/internal/config"
)

func TestWorkerClientGetsJobWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/sast/tasks/42/job" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Worker-Token") != "secret" {
			t.Fatalf("missing worker token")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"task_id":   42,
				"repo_id":   7,
				"repo_url":  "https://example.com/repo.git",
				"branch":    "main",
				"language":  "go",
				"auth_type": "none",
			},
		})
	}))
	defer server.Close()

	client := NewWorkerClient(&config.WorkerConfig{
		CallbackURL: server.URL,
		Token:       "secret",
	})
	job, err := client.GetJob(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if job.TaskID != 42 || job.RepoID != 7 || job.RepoURL != "https://example.com/repo.git" {
		t.Fatalf("unexpected job: %#v", job)
	}
}

func TestWorkerClientReturnsCallbackError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewWorkerClient(&config.WorkerConfig{
		CallbackURL: server.URL,
		Token:       "wrong",
	})
	if err := client.AppendLog(context.Background(), 1, "message"); err == nil {
		t.Fatal("expected callback error")
	}
}
