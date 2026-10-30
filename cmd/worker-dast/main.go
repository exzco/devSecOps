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
	dastMessaging "devsecops/internal/dast/messaging"
	dastScheduler "devsecops/internal/dast/scheduler"
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

	indexPath := filepath.Join(cfg.Dast.PocDir, "poc_index.json")
	if _, err := os.Stat(indexPath); err != nil {
		log.Fatalf("PoC index not found at %s: %v", indexPath, err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	dastRunner := dastEngine.NewRunner(cfg.Dast.PocDir)
	dastWorker := dastScheduler.NewWorkerRuntime(
		rdb,
		cfg.Dast.QueuePrefix,
		dastMessaging.DefaultRawStream,
		dastMessaging.DefaultTargetStream,
		dastMessaging.DefaultGroup,
		dastRunner,
	)

	go func() {
		if err := dastWorker.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[worker-dast] stopped with error: %v", err)
		}
	}()

	log.Println("[worker-dast] ready")
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	cancel()
	log.Println("[worker-dast] shutdown complete")
}
