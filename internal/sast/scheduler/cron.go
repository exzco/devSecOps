package scheduler

import (
	"log"

	"github.com/hibiken/asynq"
	"github.com/robfig/cron/v3"

	sastModel "devsecops/internal/sast/model"
	"devsecops/internal/sast/service"
)

type CronManager struct {
	cron        *cron.Cron
	repoSvc     *service.RepoService
	scanSvc     *service.ScanService
	asynqClient *asynq.Client
	schedule    string
}

func NewCronManager(repoSvc *service.RepoService, scanSvc *service.ScanService, client *asynq.Client, schedule string) *CronManager {
	if schedule == "" {
		schedule = "0 2 * * *" // default to 2:00 AM every day
	}
	return &CronManager{
		cron:        cron.New(cron.WithParser(cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow))),
		repoSvc:     repoSvc,
		scanSvc:     scanSvc,
		asynqClient: client,
		schedule:    schedule,
	}
}

func (m *CronManager) Start() {
	_, err := m.cron.AddFunc(m.schedule, func() {
		log.Println("[Cron] Starting scheduled global scan...")

		repos, err := m.repoSvc.List(1, 1000)
		if err != nil {
			log.Printf("[Cron] Failed to fetch repositories: %v", err)
			return
		}

		repoList, ok := repos.Data.([]sastModel.Repository)
		if !ok {
			log.Println("[Cron] Failed to cast repository list")
			return
		}

		for _, repo := range repoList {
			if !repo.IsActive {
				continue
			}
			if !repo.AutoScanEnabled {
				continue
			}

			task, err := m.scanSvc.CreateTask(repo.ID, sastModel.TriggerTypeCron, repo.Branch, repo.Language, "", "", "")
			if err != nil {
				log.Printf("[Cron] Failed to create scan task for repo %s: %v", repo.Name, err)
				continue
			}

			asynqTask, err := NewScanRepoTask(repo.ID, task.ID)
			if err != nil {
				log.Printf("[Cron] Failed to build async task for repo %s: %v", repo.Name, err)
				continue
			}

			info, err := m.asynqClient.Enqueue(asynqTask)
			if err != nil {
				m.scanSvc.UpdateTaskStatus(task.ID, sastModel.TaskStatusFailed, map[string]interface{}{
					"error_msg": "failed to enqueue task: " + err.Error(),
				})
				log.Printf("[Cron] Failed to enqueue async task for repo %s: %v", repo.Name, err)
				continue
			}

			log.Printf("[Cron] Enqueued scan task (ID: %d, Queue: %s) for repo %s", task.ID, info.Queue, repo.Name)
		}
	})

	if err != nil {
		log.Printf("[Cron] Failed to initialize cron schedule '%s': %v", m.schedule, err)
		return
	}

	m.cron.Start()
	log.Printf("[Cron] Scheduled global scan started with schedule: %s", m.schedule)
}

func (m *CronManager) Stop() {
	if m.cron != nil {
		m.cron.Stop()
	}
}
