package scheduler

import (
	"log"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"devsecops/internal/config"
	"devsecops/internal/sast/scanner"
)

func StartWorker(cfg *config.Config, db *gorm.DB) *asynq.Server {
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

	dispatcher := NewTaskDispatcher(db, scanner.NewScanWorker(&cfg.Scanner))

	mux := asynq.NewServeMux()
	mux.Handle(TypeScanRepo, dispatcher)

	log.Println("[Asynq Worker] 启动，等待 SAST 任务...")
	if err := srv.Start(mux); err != nil {
		log.Fatalf("[Asynq Worker] 启动失败: %v", err)
	}
	return srv
}

func NewClient(cfg *config.RedisConfig) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}
