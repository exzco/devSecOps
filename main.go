package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"devsecops/internal/config"
	dastEngine "devsecops/internal/dast/engine"
	dastHandler "devsecops/internal/dast/handler"
	dastModel "devsecops/internal/dast/model"
	dastService "devsecops/internal/dast/service"
	"devsecops/internal/model"
	"devsecops/internal/preflight"
	"devsecops/internal/router"
	sastHandler "devsecops/internal/sast/handler"
	sastModel "devsecops/internal/sast/model"
	sastScanner "devsecops/internal/sast/scanner"
	sastScheduler "devsecops/internal/sast/scheduler"
	sastService "devsecops/internal/sast/service"
	scaModel "devsecops/internal/sca/model"
)

func main() {
	configPath := os.Getenv("CONFIG_FILE")
	if configPath == "" {
		configPath = "configs/config.local.yaml"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	log.Printf("[Init] Config loaded: %s", configPath)

	preflight.RunChecks(false, false)

	db, err := model.InitDB(&cfg.Database)
	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}
	log.Println("[Init] Database connected and migrated")

	if err := db.AutoMigrate(
		&sastModel.Repository{},
		&sastModel.ScanTask{},
		&sastModel.Vulnerability{},
		&dastModel.PocTemplate{},
		&scaModel.ScaProject{},
		&scaModel.ScaScanTask{},
		&scaModel.ScaDependency{},
		&scaModel.ScaVulnerability{},
		&scaModel.ScaOsvVulnerability{},
	); err != nil {
		panic("failed to migrate domain models: " + err.Error())
	}

	//实例化 SAST 服务与 Worker
	scanWorker := sastScanner.NewScanWorker(&cfg.Scanner)
	sastRepoSvc := sastService.NewRepoService(db)
	sastScanSvc := sastService.NewScanService(db, scanWorker)

	// Break circular dependency between service and scheduler by setting callback
	sastService.ActiveTaskCanceler = func(taskID uint) {
		sastScheduler.ActiveTasksMu.Lock()
		if cancel, exists := sastScheduler.ActiveTasks[taskID]; exists {
			cancel()
		}
		sastScheduler.ActiveTasksMu.Unlock()
	}

	//  启动 Asynq 队列 Worker，负责 SAST 代码扫描
	asynqClient := sastScheduler.NewClient(&cfg.Redis)
	defer asynqClient.Close()

	asynqServer := sastScheduler.StartWorker(cfg, db)
	defer asynqServer.Shutdown()

	//  实例化 DAST 服务与后台 Worker 协程
	dastSvc := dastService.NewDastService(&cfg.Redis, cfg.Dast.QueuePrefix)
	pocSvc := dastService.NewPocService(&cfg.MinIO)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dastEngine.StartAllDastWorkers(ctx, cfg, pocSvc)

	//  构造路由 Handler 控制器并初始化路由
	handlers := &router.Handlers{
		RepoHandler:     sastHandler.NewRepoHandler(sastRepoSvc),
		ScanHandler:     sastHandler.NewScanHandler(sastScanSvc, asynqClient),
		DastCtrlHandler: dastHandler.NewDastHandler(dastSvc),
		PocHandler:      dastHandler.NewPocHandler(pocSvc),
	}
	r := router.SetupRouter(handlers)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go func() {
		log.Printf("[Server] Starting devsecops platform on: http://localhost:%d", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Server] Failed to run Gin server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("[System] Received signal: %v. Initiating graceful shutdown...", sig)

	ctxGrace, cancelGrace := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelGrace()
	if err := srv.Shutdown(ctxGrace); err != nil {
		log.Printf("[Server] Server forced to shutdown: %v", err)
	} else {
		log.Println("[Server] Server gracefully stopped")
	}
	cancel()
	log.Println("[Asynq Worker] Shutting down worker...")
	asynqServer.Shutdown()
	log.Println("[System] shutdown complete.")
}