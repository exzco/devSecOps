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
	"github.com/redis/go-redis/v9"

	"devsecops/internal"
	"devsecops/internal/config"
	"devsecops/internal/dast"
	"devsecops/internal/messaging"
	"devsecops/internal/model"
	"devsecops/internal/pipeline"
	"devsecops/internal/sast"
	"devsecops/internal/sca"
	"devsecops/internal/worker"
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
		&model.Repository{},
		&model.ScanTask{},
		&model.Vulnerability{},
		&model.ScaScanTask{},
		&model.ScaDependency{},
		&model.ScaVulnerability{},
	); err != nil {
		panic("failed to migrate domain models: " + err.Error())
	}

	sastRepoSvc := sast.NewRepoService(db)
	sastScanSvc := sast.NewScanService(db)
	scaSvc := sca.NewScaService(db, &cfg.Scanner)

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer rdb.Close()

	streamClient := messaging.NewStreamClient(rdb)
	dastSvc := dast.NewDastService(rdb, cfg.Dast)

	handlers := &internal.Handlers{
		RepoHandler:     sast.NewRepoHandler(sastRepoSvc),
		ScanHandler:     sast.NewScanHandler(sastScanSvc),
		DastCtrlHandler: dast.NewDastHandler(dastSvc),
		ScaHandler:      sca.NewScaHandler(scaSvc),
		PipelineHandler: pipeline.NewHandler(sastScanSvc, streamClient, dastSvc, scaSvc, &cfg.Scanner),
		InternalHandler: sast.NewInternalHandler(sastScanSvc, cfg.Worker.Token, cfg.Scanner.WorkDir),
		WorkerHandler:   worker.NewWorkerHandler(rdb),
	}
	r := internal.SetupRouter(handlers)

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
				log.Printf("[Server] Note: tcp6 server stopped: %v", err)
			}
		}()
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[Server] Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[Server] Server forced to shutdown: %v", err)
	}

	log.Println("[Server] Server exiting")
}
