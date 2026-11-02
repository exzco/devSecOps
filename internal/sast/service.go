package sast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/model"
	"devsecops/internal/worker"
)


type RepoService struct {
	db *gorm.DB
}

func NewRepoService(db *gorm.DB) *RepoService {
	return &RepoService{db: db}
}

func (s *RepoService) Create(req *model.RepoRequest) (*model.Repository, error) {
	repo := &model.Repository{
		Name:       req.Name,
		URL:        req.URL,
		Branch:     req.Branch,
		Language:   req.Language,
		AuthType:   req.AuthType,
		AuthSecret: req.AuthSecret,
	}

	if repo.Branch == "" {
		repo.Branch = "main"
	}
	if repo.AuthType == "" {
		repo.AuthType = "none"
	}
	if err := s.db.Create(repo).Error; err != nil {
		return nil, err
	}
	return repo, nil
}

func (s *RepoService) GetByID(id uint) (*model.Repository, error) {
	var repo model.Repository
	if err := s.db.First(&repo, id).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *RepoService) List(page, perPage int) (*model.PaginatedResponse, error) {
	page, perPage = model.NormalizePagination(page, perPage)

	var repos []model.Repository
	var total int64

	if err := s.db.Model(&model.Repository{}).Count(&total).Error; err != nil {
		return nil, err
	}
	offset := (page - 1) * perPage
	if err := s.db.Order("id DESC").Offset(offset).Limit(perPage).Find(&repos).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(repos, total, page, perPage), nil
}

func (s *RepoService) Update(id uint, req *model.RepoRequest) (*model.Repository, error) {
	repo, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.URL != "" {
		updates["url"] = req.URL
	}
	if req.Branch != "" {
		updates["branch"] = req.Branch
	}
	if req.Language != "" {
		updates["language"] = req.Language
	}
	if req.AuthType != "" {
		updates["auth_type"] = req.AuthType
	}
	if req.AuthSecret != "" {
		updates["auth_secret"] = req.AuthSecret
	}
	if err := s.db.Model(repo).Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetByID(id)
}

func (s *RepoService) Delete(id uint) error {
	return s.DeleteBatch([]uint{id})
}

func (s *RepoService) BatchDelete(ids []uint) error {
	return s.DeleteBatch(ids)
}

func (s *RepoService) DeleteBatch(ids []uint) error {
	if len(ids) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("repo_id IN ?", ids).Delete(&model.Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("repo_id IN ?", ids).Delete(&model.ScanTask{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("id IN ?", ids).Delete(&model.Repository{}).Error; err != nil {
			return err
		}
		return nil
	})
}

// 2. ScanService SAST 扫描任务调度分发与结果持久化

type ScanService struct {
	db  *gorm.DB
	rdb *redis.Client
}

func NewScanService(db *gorm.DB, rdb ...*redis.Client) *ScanService {
	svc := &ScanService{db: db}
	if len(rdb) > 0 {
		svc.rdb = rdb[0]
	}
	return svc
}

// ReconcileOrphanTasks 探测并自愈离线 Worker 的遗留孤儿任务及超时卡死任务
func (s *ScanService) ReconcileOrphanTasks(ctx context.Context, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		timeout = 60 * time.Minute
	}

	var activeTasks []model.ScanTask
	if err := s.db.Where("status IN (?)", []string{model.TaskStatusPending, model.TaskStatusRunning}).Find(&activeTasks).Error; err != nil {
		return 0, fmt.Errorf("query active scan tasks: %w", err)
	}

	reconciled := 0
	now := time.Now()

	for _, task := range activeTasks {
		isOrphan := false
		reason := ""

		switch task.Status {
		case model.TaskStatusRunning:
			// 1. 如果绑定了 worker_id，检查该 worker 是否在 Redis 中持有有效心跳
			if task.WorkerID != "" && s.rdb != nil {
				key := fmt.Sprintf("%s%s:%s", worker.KeyWorkerPrefix, worker.TypeSAST, task.WorkerID)
				val, err := s.rdb.Get(ctx, key).Result()
				if (err == redis.Nil || val == "") && time.Since(task.UpdatedAt) > 5*time.Minute {
					isOrphan = true
					reason = fmt.Sprintf("执行节点 %s 已离线且超过 5 分钟未上报进度", task.WorkerID)
				}
			}

			// 2. 如果未绑定 worker_id，但任务已处于 running 且超过 10 分钟未更新进度
			if !isOrphan && task.WorkerID == "" && time.Since(task.UpdatedAt) > 10*time.Minute {
				isOrphan = true
				reason = "任务已被分配执行，但未关联有效 Worker 节点且超过 10 分钟无心跳响应"
			}

			// 3. 任务整体运行时间超过设定阈值（默认 60 分钟）未更新
			if !isOrphan && time.Since(task.UpdatedAt) > timeout {
				isOrphan = true
				reason = fmt.Sprintf("任务执行已超过 %v 未更新，触发超时自愈拦截", timeout)
			}

		case model.TaskStatusPending:
			// 任务排队超过 24 小时未被任何 Worker 领取
			if time.Since(task.CreatedAt) > 24*time.Hour {
				isOrphan = true
				reason = "任务在队列中等待超过 24 小时，无可用 Worker 节点领取执行"
			}
		}

		if isOrphan {
			duration := int64(0)
			if task.StartedAt != nil {
				duration = now.Sub(*task.StartedAt).Milliseconds()
			}
			finishedAt := now

			err := s.db.Model(&model.ScanTask{}).Where("id = ?", task.ID).Updates(map[string]interface{}{
				"status":      model.TaskStatusFailed,
				"finished_at": finishedAt,
				"duration_ms": duration,
				"error_msg":   reason,
			}).Error
			if err != nil {
				log.Printf("[OrphanReaper] 自愈任务 #%d 失败: %v", task.ID, err)
				continue
			}

			_ = s.AppendTaskLog(task.ID, fmt.Sprintf("系统自愈干预: %s，状态已自动置为失败", reason))
			reconciled++
			log.Printf("[OrphanReaper] 成功自愈孤儿任务 #%d (原状态: %s, 原因: %s)", task.ID, task.Status, reason)
		}
	}

	return reconciled, nil
}

func (s *ScanService) CreateTask(repoID uint, triggerType, branch, language, querySuite, ruleProfile, rules string) (*model.ScanTask, error) {
	task := &model.ScanTask{
		RepoID:      repoID,
		TriggerType: triggerType,
		Branch:      branch,
		Language:    language,
		QuerySuite:  querySuite,
		RuleProfile: ruleProfile,
		Rules:       rules,
	}
	task.Status = model.TaskStatusPending

	if err := s.db.Create(task).Error; err != nil {
		return nil, err
	}
	return task, nil
}

func (s *ScanService) CountVulnerabilitySeverities(taskID uint) (map[string]int, error) {
	var rows []struct {
		Severity string
		Count    int
	}
	if err := s.db.Model(&model.Vulnerability{}).
		Select("LOWER(severity) AS severity, COUNT(*) AS count").
		Where("scan_task_id = ?", taskID).
		Group("LOWER(severity)").
		Scan(&rows).Error; err != nil {
		return nil, err
	}

	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		if row.Severity != "" {
			counts[row.Severity] = row.Count
		}
	}
	return counts, nil
}

func (s *ScanService) GetTask(id uint) (*model.ScanTask, error) {
	var task model.ScanTask
	if err := s.db.Preload("Repository").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *ScanService) ListTasks(query *model.ListQuery) (*model.PaginatedResponse, error) {
	page, perPage := model.NormalizePagination(query.Page, query.PerPage)

	db := s.db.Model(&model.ScanTask{})
	if query.RepoID > 0 {
		db = db.Where("repo_id = ?", query.RepoID)
	}
	if query.Status != "" {
		db = db.Where("status = ?", query.Status)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	var tasks []model.ScanTask
	offset := (page - 1) * perPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(perPage).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(tasks, total, page, perPage), nil
}

func (s *ScanService) UpdateTask(taskID uint, updates map[string]interface{}) error {
	return s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (s *ScanService) UpdateTaskStatus(taskID uint, status string, updates map[string]interface{}) error {
	if updates == nil {
		updates = map[string]interface{}{}
	}
	updates["status"] = status
	return s.db.Model(&model.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (s *ScanService) AppendExecutionLog(taskID uint, logText string) error {
	if strings.TrimSpace(logText) == "" {
		return nil
	}
	return s.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Update("execution_log", gorm.Expr("COALESCE(execution_log, '') || ?", logText)).Error
}

func (s *ScanService) AppendTaskLog(taskID uint, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	return s.AppendExecutionLog(taskID, line)
}

func (s *ScanService) SaveResults(repoID, taskID uint, repoURL string, results []Vulnerability) error {
	if taskID == 0 {
		return errors.New("invalid task id: 0")
	}

	seen := make(map[string]struct{}, len(results))
	vulnerabilities := make([]model.Vulnerability, 0, len(results))
	for _, result := range results {
		if result.Fingerprint != "" {
			if _, ok := seen[result.Fingerprint]; ok {
				continue
			}
			seen[result.Fingerprint] = struct{}{}
		}

		dataFlowJSON, err := json.Marshal(result.DataFlow)
		if err != nil {
			return fmt.Errorf("marshal data flow: %w", err)
		}
		vulnerabilities = append(vulnerabilities, model.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			RepoURL:     repoURL,
			FilePath:    result.FilePath,
			StartLine:   result.StartLine,
			EndLine:     result.EndLine,
			CodeSnippet: result.CodeSnippet,
			Fingerprint: result.Fingerprint,
			DataFlow:    datatypes.JSON(dataFlowJSON),
			BaseVulnerability: model.BaseVulnerability{
				RuleID:   result.RuleID,
				RuleName: result.RuleName,
				Severity: result.Severity,
				Message:  result.Message,
				Status:   model.VulnStatusNew,
			},
		})
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("scan_task_id = ?", taskID).Delete(&model.Vulnerability{}).Error; err != nil {
			return fmt.Errorf("clear existing vulnerabilities for task %d: %w", taskID, err)
		}
		if len(vulnerabilities) > 0 {
			if err := tx.CreateInBatches(vulnerabilities, 500).Error; err != nil {
				return fmt.Errorf("bulk insert vulnerabilities: %w", err)
			}
		}
		return nil
	})
}

func (s *ScanService) ListVulnerabilities(query *model.ListQuery) (*model.PaginatedResponse, error) {
	page, perPage := model.NormalizePagination(query.Page, query.PerPage)

	db := s.db.Model(&model.Vulnerability{})
	if query.RepoID > 0 {
		db = db.Where("repo_id = ?", query.RepoID)
	}
	if query.TaskID > 0 {
		db = db.Where("scan_task_id = ?", query.TaskID)
	}
	if query.Severity != "" {
		db = db.Where("severity = ?", query.Severity)
	}
	if query.Status != "" {
		db = db.Where("status = ?", query.Status)
	}
	if query.RuleID != "" {
		db = db.Where("rule_id = ?", query.RuleID)
	}
	if query.Keyword != "" {
		kw := "%" + query.Keyword + "%"
		db = db.Where("rule_id ILIKE ? OR rule_name ILIKE ? OR file_path ILIKE ? OR message ILIKE ?", kw, kw, kw, kw)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, err
	}

	var vulns []model.Vulnerability
	offset := (page - 1) * perPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(perPage).Find(&vulns).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(vulns, total, page, perPage), nil
}

func (s *ScanService) DeleteTask(taskID uint, force ...bool) error {
	task, err := s.GetTask(taskID)
	if err != nil {
		return err
	}

	isForce := len(force) > 0 && force[0]

	if task.Status == model.TaskStatusPending || task.Status == model.TaskStatusRunning {
		// 允许条件：
		// 1. 显式指定 force=true
		// 2. 任务距离最后一次更新已超过 60 分钟（被遗弃或超时的死任务）
		isStale := time.Since(task.UpdatedAt) > 60*time.Minute
		if !isForce && !isStale {
			return errors.New("cannot delete a running or pending task (use ?force=true or wait 60 minutes after last update)")
		}
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("scan_task_id = ?", taskID).Delete(&model.Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Delete(&model.ScanTask{}, taskID).Error; err != nil {
			return err
		}
		return nil
	})
}
