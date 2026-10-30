package scheduler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"devsecops/internal/config"
	"devsecops/internal/messaging"
	"devsecops/internal/sast"
	"devsecops/internal/sast/scanner"
)

type TaskDispatcher struct {
	worker *scanner.ScanWorker
	client *WorkerClient
}

func NewTaskDispatcher(worker *scanner.ScanWorker, client *WorkerClient) *TaskDispatcher {
	return &TaskDispatcher{worker: worker, client: client}
}

// Dispatch 处理来自 Redis Streams 的扫描任务
func (d *TaskDispatcher) Dispatch(ctx context.Context, payload messaging.SASTTaskMessage) error {
	job, err := d.client.GetJob(ctx, payload.TaskID)
	if err != nil {
		return fmt.Errorf("fetch scan job %d: %w", payload.TaskID, err)
	}

	workerID, _ := os.Hostname()
	startedAt := time.Now()
	progress := func(message string) {
		if err := d.client.AppendLog(ctx, job.TaskID, message); err != nil {
			log.Printf("[worker-sast] failed to append task log %d: %v", job.TaskID, err)
		}
	}

	_ = d.client.AppendLog(ctx, job.TaskID, fmt.Sprintf("任务已由 %s 领取", workerID))

	vulnerabilities, sarifPath, scanErr := d.worker.RunScan(
		ctx,
		job,
		progress,
	)
	duration := time.Since(startedAt).Milliseconds()
	if scanErr != nil {
		failErr := d.client.Fail(ctx, job.TaskID, sast.Callback{
			Error:      scanErr.Error(),
			DurationMs: duration,
			CommitSHA:  job.CommitSHA,
			WorkerID:   workerID,
		})
		if failErr != nil {
			return fmt.Errorf("scan failed: %v; callback failed: %w", scanErr, failErr)
		}
		return fmt.Errorf("scan failed: %w", scanErr)
	}

	sarifData, err := os.ReadFile(sarifPath)
	if err != nil {
		return fmt.Errorf("read SARIF result: %w", err)
	}
	if err := d.client.Complete(ctx, job.TaskID, sast.Callback{
		SARIF:           sarifData,
		Vulnerabilities: vulnerabilities,
		DurationMs:      duration,
		CommitSHA:       job.CommitSHA,
		WorkerID:        workerID,
	}); err != nil {
		return fmt.Errorf("complete scan %d: %w", job.TaskID, err)
	}
	return nil
}

type WorkerClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func NewWorkerClient(cfg *config.WorkerConfig) *WorkerClient {
	return &WorkerClient{
		baseURL: strings.TrimRight(cfg.CallbackURL, "/"),
		token:   cfg.Token,
		client:  &http.Client{Timeout: 2 * time.Minute},
	}
}

func (c *WorkerClient) GetJob(ctx context.Context, taskID uint) (*sast.Job, error) {
	var response struct {
		Data sast.Job `json:"data"`
	}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/internal/v1/sast/tasks/%d/job", taskID), nil, &response); err != nil {
		return nil, err
	}
	return &response.Data, nil
}

func (c *WorkerClient) AppendLog(ctx context.Context, taskID uint, message string) error {
	if strings.TrimSpace(message) == "" {
		return nil
	}
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/internal/v1/sast/tasks/%d/logs", taskID), sast.Callback{Message: message}, nil)
}

func (c *WorkerClient) Complete(ctx context.Context, taskID uint, request sast.Callback) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/internal/v1/sast/tasks/%d/complete", taskID), request, nil)
}

func (c *WorkerClient) Fail(ctx context.Context, taskID uint, request sast.Callback) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/internal/v1/sast/tasks/%d/fail", taskID), request, nil)
}

func (c *WorkerClient) do(ctx context.Context, method, endpoint string, requestBody, responseBody any) error {
	var body io.Reader
	if requestBody != nil {
		data, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Worker-Token", c.token)
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if responseBody != nil && len(data) > 0 {
		if err := json.Unmarshal(data, responseBody); err != nil {
			return fmt.Errorf("decode worker callback response: %w", err)
		}
	}
	return nil
}
