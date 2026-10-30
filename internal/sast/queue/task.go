package queue

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"

	"devsecops/internal/config"
)

const TypeScanRepo = "scan:repo"

type ScanRepoPayload struct {
	RepoID uint `json:"repo_id"`
	TaskID uint `json:"task_id"`
}

func NewClient(cfg *config.RedisConfig) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

func NewScanRepoTask(repoID, taskID uint, timeoutMinutes int) (*asynq.Task, error) {
	payload, err := json.Marshal(ScanRepoPayload{
		RepoID: repoID,
		TaskID: taskID,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal task payload: %w", err)
	}
	if timeoutMinutes <= 0 {
		timeoutMinutes = 30
	}
	return asynq.NewTask(
		TypeScanRepo,
		payload,
		asynq.MaxRetry(0),
		asynq.Queue("scans"),
		asynq.Timeout(time.Duration(timeoutMinutes)*time.Minute),
	), nil
}
