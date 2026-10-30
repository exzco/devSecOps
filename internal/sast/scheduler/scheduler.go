package scheduler

import (
	"fmt"
	"log"

	"github.com/hibiken/asynq"

	"devsecops/internal/config"
	"devsecops/internal/sast/queue"
	"devsecops/internal/sast/scanner"
)

func StartWorker(cfg *config.Config) (*asynq.Server, error) {
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

	dispatcher := NewTaskDispatcher(
		scanner.NewScanWorker(&cfg.Scanner),
		NewWorkerClient(&cfg.Worker),
	)

	mux := asynq.NewServeMux()
	mux.Handle(queue.TypeScanRepo, dispatcher)

	log.Println("[Asynq Worker] 启动，等待 SAST 任务...")
	if err := srv.Start(mux); err != nil {
		return nil, fmt.Errorf("start asynq worker: %w", err)
	}
	return srv, nil
}
