package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"devsecops/internal/config"
	sastScheduler "devsecops/internal/sast/scheduler"
)

func main() {
	configPathFlag := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	cfg, err := config.LoadConfig(config.ResolvePath(*configPathFlag))
	if err != nil {
		log.Fatalf("failed to load worker config: %v", err)
	}

	asynqServer, err := sastScheduler.StartWorker(cfg)
	if err != nil {
		log.Fatalf("failed to start SAST worker: %v", err)
	}
	defer asynqServer.Shutdown()

	log.Println("[worker-sast] ready")
	waitForShutdown()
	log.Println("[worker-sast] shutdown complete")
}

func waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}
