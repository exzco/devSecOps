package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"devsecops/internal/config"
	dastHandler "devsecops/internal/dast/handler"
	dastService "devsecops/internal/dast/service"
	"devsecops/internal/model"
	"devsecops/internal/pipeline"
	"devsecops/internal/router"
	sastHandler "devsecops/internal/sast/handler"
	sastModel "devsecops/internal/sast/model"
	sastQueue "devsecops/internal/sast/queue"
	sastService "devsecops/internal/sast/service"
	scaHandler "devsecops/internal/sca/handler"
	scaModel "devsecops/internal/sca/model"
	scaService "devsecops/internal/sca/service"
)

func main() {
	configPathFlag := flag.String("config", "", "Path to YAML configuration file")
	flag.Parse()

	configPath := config.ResolvePath(*configPathFlag)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		panic("failed to load config: " + err.Error())
	}
	log.Printf("[Server-Init] Config loaded from %s", configPath)

	if cfg.Server.Mode == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	db, err := model.InitDB(&cfg.Database)
	if err != nil {
		panic("failed to initialize database: " + err.Error())
	}
	log.Println("[Server-Init] Database connected and migrated")

	if err := db.AutoMigrate(
		&sastModel.Repository{},
		&sastModel.ScanTask{},
		&sastModel.Vulnerability{},
		&scaModel.ScaScanTask{},
		&scaModel.ScaDependency{},
		&scaModel.ScaVulnerability{},
	); err != nil {
		panic("failed to migrate domain models: " + err.Error())
	}

	sastRepoSvc := sastService.NewRepoService(db)
	sastScanSvc := sastService.NewScanService(db)
	scaSvc := scaService.NewScaService(db, &cfg.Scanner)

	asynqClient := sastQueue.NewClient(&cfg.Redis)
	defer asynqClient.Close()

	dastSvc := dastService.NewDastService(&cfg.Redis, cfg.Dast)
	defer dastSvc.Close()

	handlers := &router.Handlers{
		RepoHandler:     sastHandler.NewRepoHandler(sastRepoSvc),
		ScanHandler:     sastHandler.NewScanHandler(sastScanSvc),
		DastCtrlHandler: dastHandler.NewDastHandler(dastSvc),
		ScaHandler:      scaHandler.NewScaHandler(scaSvc),
		PipelineHandler: pipeline.NewHandler(sastScanSvc, asynqClient, dastSvc, scaSvc, &cfg.Scanner),
		InternalHandler: sastHandler.NewInternalHandler(sastScanSvc, cfg.Worker.Token, cfg.Scanner.WorkDir),
	}
	r := router.SetupRouter(handlers)

	srv := &http.Server{
		Handler: r,
	}

	ln4, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", cfg.Server.Port))
	if err != nil {
		log.Fatalf("[Server] Failed to listen on tcp4: %v", err)
	}

	ln6, _ := net.Listen("tcp6", fmt.Sprintf("[::]:%d", cfg.Server.Port))

	go func() {
		log.Printf("[Server] DevSecOps Central Platform listening on: http://0.0.0.0:%d and http://[::]:%d", cfg.Server.Port, cfg.Server.Port)
		if err := srv.Serve(ln4); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[Server] Failed to run HTTP server on tcp4: %v", err)
		}
	}()

	if ln6 != nil {
		go func() {
			if err := srv.Serve(ln6); err != nil && err != http.ErrServerClosed {
				log.Printf("[Server] tcp6 server stopped: %v", err)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[Server] Shutting down DevSecOps Central Platform...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("[Server] Shutdown error: %v", err)
	}
	log.Println("[Server] Server stopped successfully")
}
