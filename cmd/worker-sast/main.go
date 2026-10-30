package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	sastScheduler "devsecops/internal/sast/scheduler"
	"devsecops/internal/worker"
)

func main() {
	configPathFlag := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(config.ResolvePath(*configPathFlag))
	if err != nil {
		log.Fatalf("failed to load worker config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[worker-sast] 无法连接 Redis 服务 (%s): %v", cfg.Redis.Addr, err)
	}

	// 初始化心跳与环境自检上报器
	reporter := worker.NewHeartbeatReporter(
		rdb,
		worker.TypeSAST,
		cfg.Scanner.WorkDir,
		func() ([]worker.DependencyStatus, []string) {
			return worker.DiagnoseSAST(&cfg.Scanner)
		},
	)
	reporter.Start(ctx)

	// 启动 SAST 任务流监听调度器
	_, err = sastScheduler.StartWorker(ctx, cfg, rdb, reporter)
	if err != nil {
		log.Fatalf("failed to start SAST worker: %v", err)
	}

	log.Printf("[worker-sast] 节点已上线并就绪: WorkerID=%s", reporter.WorkerID())
	waitForShutdown()
	cancel()
	log.Println("[worker-sast] shutdown complete")
}

func waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}
