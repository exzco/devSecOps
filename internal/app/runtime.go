package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/hibiken/asynq"
	"gorm.io/gorm"

	"devsecops/internal/config"
	dastEngine "devsecops/internal/dast/engine"
	dastHandler "devsecops/internal/dast/handler"
	dastService "devsecops/internal/dast/service"
	"devsecops/internal/router"
	sastAsync "devsecops/internal/sast/async"
	sastHandler "devsecops/internal/sast/handler"
	sastService "devsecops/internal/sast/service"
	scaHandler "devsecops/internal/sca/handler"
	scaService "devsecops/internal/sca/service"
)

type Runtime struct {
	Server      *http.Server
	asynqServer *asynq.Server
	asynqClient *asynq.Client
	dastQueue   *dastService.QueueClient
	stopDAST    context.CancelFunc
}

func NewRuntime(cfg *config.Config, db *gorm.DB) (*Runtime, error) {
	sastRepoSvc := sastService.NewRepoService(db)
	sastScanSvc := sastService.NewScanService(db)

	asynqClient := sastAsync.NewClient(&cfg.Redis)
	asynqServer, err := sastAsync.StartWorker(cfg, db)
	if err != nil {
		_ = asynqClient.Close()
		return nil, err
	}

	dastKeys := dastService.NewQueueKeys(cfg.Dast.QueuePrefix)
	dastQueueClient, err := dastService.NewQueueClient(cfg.Redis, cfg.DastDialTimeout(), cfg.DastReadTimeout())
	if err != nil {
		asynqServer.Shutdown()
		_ = asynqClient.Close()
		return nil, err
	}

	dastSvc := dastService.NewDastService(dastQueueClient.Rdb, dastKeys, cfg.Dast.DefaultPorts)
	pocSvc, err := dastService.NewPocService(&cfg.MinIO)
	if err != nil {
		_ = dastQueueClient.Close()
		asynqServer.Shutdown()
		_ = asynqClient.Close()
		return nil, err
	}

	scaSvc := scaService.NewScaService(db)
	cveAiSvc := dastService.NewCveAiService(db, dastQueueClient.Rdb, pocSvc, cfg.OpenAI)

	dastCtx, stopDAST := context.WithCancel(context.Background())
	dastEngine.StartAllDastWorkers(dastCtx, cfg, dastQueueClient, dastKeys, pocSvc)

	handlers := &router.Handlers{
		RepoHandler:     sastHandler.NewRepoHandler(sastRepoSvc),
		ScanHandler:     sastHandler.NewScanHandler(sastScanSvc, asynqClient),
		DastCtrlHandler: dastHandler.NewDastHandler(dastSvc),
		PocHandler:      dastHandler.NewPocHandler(pocSvc),
		ScaHandler:      scaHandler.NewScaHandler(scaSvc),
		CveAiHandler:    dastHandler.NewCveAiHandler(cveAiSvc),
	}

	return &Runtime{
		Server: &http.Server{
			Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
			Handler: router.SetupRouter(handlers),
		},
		asynqServer: asynqServer,
		asynqClient: asynqClient,
		dastQueue:   dastQueueClient,
		stopDAST:    stopDAST,
	}, nil
}

func (r *Runtime) Shutdown(ctx context.Context) error {
	httpErr := r.Server.Shutdown(ctx)
	r.stopDAST()
	r.asynqServer.Shutdown()
	asynqErr := r.asynqClient.Close()

	var dastErr error
	if r.dastQueue != nil {
		dastErr = r.dastQueue.Close()
	}

	return errors.Join(httpErr, asynqErr, dastErr)
}
