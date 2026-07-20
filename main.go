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

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"devsecops/internal/config"
	dastEngine "devsecops/internal/dast/engine"
	dastHandler "devsecops/internal/dast/handler"
	dastModel "devsecops/internal/dast/model"
	dastService "devsecops/internal/dast/service"
	"devsecops/internal/model"
	"devsecops/internal/preflight"
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

	preflight.RunChecks(true, true)

	db, err := model.InitDB(&cfg.Database)
	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}
	log.Println("[Init] Database connected and migrated")

	// Migrate domain-specific tables to break circular imports in internal/model package
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

	//  构造路由 Handler 控制器
	repoHandler := sastHandler.NewRepoHandler(sastRepoSvc)
	scanHandler := sastHandler.NewScanHandler(sastScanSvc, asynqClient)
	dastCtrlHandler := dastHandler.NewDastHandler(dastSvc)
	pocHandler := dastHandler.NewPocHandler(pocSvc)

	//  启动 Gin 路由器
	r := gin.Default()
	r.Use(cors.Default())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		// SAST 代码仓库路由
		v1.POST("/repos", repoHandler.CreateRepos)
		v1.GET("/repos/list", repoHandler.ListRepos)
		v1.POST("/repos/update/:id", repoHandler.UpdateRepos)
		v1.POST("/repos/delete/:id", repoHandler.DeleteRepos)
		v1.POST("/repos/batch-delete", repoHandler.BatchDeleteRepos)

		// SAST 扫描任务路由
		v1.POST("/scan/tasks", scanHandler.CreateTask)
		v1.POST("/scan/tasks/delete/:id", scanHandler.DeleteTask)
		v1.GET("/scan/ListTasks", scanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", scanHandler.ListVulnerabilities)
		v1.GET("/scan/tasks/:id/logs", scanHandler.GetTaskLogs)
		v1.GET("/scan/tasks/:id/sarif", scanHandler.ExportSARIF)
		v1.GET("/scan/tasks/:id/sarif/summary", scanHandler.GetSARIFSummary)

		// DAST 路由
		v1.POST("/dast/scan/tasks", dastCtrlHandler.CreateTask)
		v1.GET("/dast/scan/tasks", dastCtrlHandler.ListTasks)
		v1.GET("/dast/scan/tasks/:id/status", dastCtrlHandler.GetTaskStatus)
		v1.GET("/dast/scan/tasks/:id/results", dastCtrlHandler.GetTaskResults)
		v1.GET("/dast/scan/tasks/:id/assets", dastCtrlHandler.GetTaskAssets)
		v1.POST("/dast/scan/tasks/delete/:id", dastCtrlHandler.DeleteTask)
		v1.POST("/dast/scan/tasks/stop/:id", dastCtrlHandler.StopTask)

		// DAST 扫描配置模板路由（持久化，与扫描执行记录互不干扰）
		v1.GET("/dast/scan/configs", dastCtrlHandler.ListConfigs)
		v1.POST("/dast/scan/configs", dastCtrlHandler.CreateConfig)
		v1.POST("/dast/scan/configs/update/:id", dastCtrlHandler.UpdateConfig)
		v1.POST("/dast/scan/configs/delete/:id", dastCtrlHandler.DeleteConfig)

		// DAST PoC 路由
		v1.POST("/dast/pocs", pocHandler.CreatePoc)
		v1.GET("/dast/pocs", pocHandler.ListPocs)
		v1.GET("/dast/pocs/:id", pocHandler.GetPoc)
		v1.POST("/dast/pocs/update/:id", pocHandler.UpdatePoc)
		v1.POST("/dast/pocs/delete/:id", pocHandler.DeletePoc)
	}

	// 静态前端资源挂载
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	r.StaticFile("/icons.svg", "./web/dist/icons.svg")

	r.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File("./web/dist/index.html")
	})

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