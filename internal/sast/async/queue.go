package async

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"devsecops/internal/config"
	"devsecops/pkg/logger"
	"devsecops/internal/sast/scanner"
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
		return nil, fmt.Errorf("serialize task payload: %w", err)
	}

	return asynq.NewTask(
		TypeScanRepo,
		payload,
		asynq.MaxRetry(0),
		asynq.Queue("scans"),
		asynq.Timeout(30*time.Minute),
	), nil
}

func StartWorker(cfg *config.Config, db *gorm.DB) (*asynq.Server, error) {
	srv := asynq.NewServer(
		asynq.RedisClientOpt{
			Addr:     cfg.Redis.Addr,
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		},
		asynq.Config{
			Concurrency: cfg.Scanner.MaxConcurrent,
			Queues: map[string]int{
				"scans":   6,
				"default": 3,
			},
		},
	)

	runner := NewTaskRunner(db, scanner.NewScanWorker(&cfg.Scanner), cfg.OpenAI)

	mux := asynq.NewServeMux()
	mux.Handle(TypeScanRepo, runner)

	logger.SAST("Worker", "starting SAST scan worker...")
	if err := srv.Start(mux); err != nil {
		return nil, fmt.Errorf("start asynq worker: %w", err)
	}
	return srv, nil
}

func NewClient(cfg *config.RedisConfig) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}
