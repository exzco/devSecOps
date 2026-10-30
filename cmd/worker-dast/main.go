package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	dastEngine "devsecops/internal/dast/engine"
	dastScheduler "devsecops/internal/dast/scheduler"
	"devsecops/internal/messaging"
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
		log.Fatalf("[worker-dast] 无法连接 Redis 服务 (%s): %v", cfg.Redis.Addr, err)
	}

	// 心跳与环境自检上报
	reporter := worker.NewHeartbeatReporter(
		rdb,
		worker.TypeDAST,
		cfg.Dast.PocDir,
		func() ([]worker.DependencyStatus, []string) {
			return worker.DiagnoseDAST(&cfg.Dast)
		},
	)
	reporter.Start(ctx)

	indexPath := filepath.Join(cfg.Dast.PocDir, "poc_index.json")
	if _, err := os.Stat(indexPath); err != nil {
		log.Printf("[worker-dast] [!] 警告: PoC 规则索引文件未找到 (%s): %v, 看板将标记环境不就绪", indexPath, err)
	}

	dastRunner := dastEngine.NewRunner(cfg.Dast.PocDir)
	dastWorker := dastScheduler.NewWorkerRuntime(
		rdb,
		cfg.Dast.QueuePrefix,
		messaging.DefaultRawStream,
		messaging.DefaultTargetStream,
		messaging.DefaultGroup,
		dastRunner,
	)

	go func() {
		if err := dastWorker.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[worker-dast] stopped with error: %v", err)
		}
	}()

	log.Printf("[worker-dast] 节点已上线并就绪: WorkerID=%s", reporter.WorkerID())
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cancel()
	log.Println("[worker-dast] shutdown complete")
}
