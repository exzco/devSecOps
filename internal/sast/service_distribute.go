package sast

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/model"
)

// ==========================================
// 1. RepoService 仓库元数据管理与持久化分发
// ==========================================

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

// ==========================================
// 2. ScanService SAST 扫描任务调度分发与结果持久化
// ==========================================

type ScanService struct {
	db *gorm.DB
}

func NewScanService(db *gorm.DB) *ScanService {
	return &ScanService{db: db}
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
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, result := range results {
			dataFlowJSON, err := json.Marshal(result.DataFlow)
			if err != nil {
				return fmt.Errorf("marshal data flow: %w", err)
			}
			vulnerability := &model.Vulnerability{
				ScanTaskID:  taskID,
				RepoID:      repoID,
				Fingerprint: result.Fingerprint,
			}
			if err := tx.Where("repo_id = ? AND fingerprint = ?", repoID, result.Fingerprint).
				Assign(map[string]interface{}{
					"scan_task_id": taskID,
					"repo_url":     repoURL,
					"file_path":    result.FilePath,
					"start_line":   result.StartLine,
					"end_line":     result.EndLine,
					"message":      result.Message,
					"severity":     result.Severity,
					"rule_id":      result.RuleID,
					"rule_name":    result.RuleName,
					"code_snippet": result.CodeSnippet,
					"fingerprint":  result.Fingerprint,
					"data_flow":    datatypes.JSON(dataFlowJSON),
					"status":       model.VulnStatusNew,
				}).
				FirstOrCreate(vulnerability).Error; err != nil {
				return fmt.Errorf("save vulnerability %s: %w", result.Fingerprint, err)
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

func (s *ScanService) DeleteTask(taskID uint) error {
	task, err := s.GetTask(taskID)
	if err != nil {
		return err
	}
	if task.Status == model.TaskStatusPending || task.Status == model.TaskStatusRunning {
		return errors.New("cannot delete a running or pending task")
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
