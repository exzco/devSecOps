package scheduler

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

const (
	TypeScanRepo = "scan:repo"
	TypeAIReview = "ai:review"
)

type ScanRepoPayload struct {
	RepoID uint `json:"repo_id"`
	TaskID uint `json:"task_id"`
}

func NewScanRepoTask(repoID, taskID uint) (*asynq.Task, error) {
	payload, err := json.Marshal(ScanRepoPayload{
		RepoID: repoID,
		TaskID: taskID,
	})
	if err != nil {
		return nil, fmt.Errorf("序列化任务载荷失败: %w", err)
	}

	return asynq.NewTask(
		TypeScanRepo,
		payload,
		asynq.MaxRetry(0),
		asynq.Queue("scans"),
		asynq.Timeout(30*time.Minute),
	), nil
}
