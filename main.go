package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"devsecops/internal/app"
	"devsecops/internal/preflight"
	"devsecops/pkg/logger"
)

// AppVersion represents the current platform version (Major for big changes, Minor for small changes)
const AppVersion = "v2.2"

func main() {
	printBanner()

	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		logger.APP("Init", "failed to load config: %v", err)
		os.Exit(1)
	}

	preflight.RunChecks(false, false)

	db, err := app.InitDatabase(cfg)
	if err != nil {
		logger.APP("Init", "failed to init db: %v", err)
		os.Exit(1)
	}
	if err := app.MigrateDatabase(db); err != nil {
		logger.APP("Init", "failed to migrate db: %v", err)
		os.Exit(1)
	}
	rt, err := app.NewRuntime(cfg, db)
	if err != nil {
		logger.APP("Init", "failed to create runtime: %v", err)
		os.Exit(1)
	}

	go func() {
		logger.APP("Server", "DevSecOps Platform (%s) Listening on: http://localhost:%d", AppVersion, cfg.Server.Port)
		if err := rt.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.APP("Server", "Failed to run Gin server: %v", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.APP("System", "Received signal: %v. Initiating graceful shutdown...", sig)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rt.Shutdown(shutdownCtx); err != nil {
		logger.APP("System", "Shutdown completed with error: %v", err)
	} else {
		logger.APP("System", "Shutdown complete.")
	}
}

func printBanner() {
	fmt.Printf("\n===================================================================\n")
	fmt.Printf("📌  Current System Version : %s\n", AppVersion)
	fmt.Printf("===================================================================\n\n")
	os.Stdout.Sync()
}
