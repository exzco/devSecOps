package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/model"
	"devsecops/internal/sast/contract"
	sastModel "devsecops/internal/sast/model"
)

type ScanService struct {
	db *gorm.DB
}

func NewScanService(db *gorm.DB) *ScanService {
	return &ScanService{db: db}
}

func (s *ScanService) CreateTask(repoID uint, triggerType, branch, language, querySuite, ruleProfile, rules string) (*sastModel.ScanTask, error) {
	task := &sastModel.ScanTask{
		RepoID:      repoID,
		TriggerType: triggerType,
		Branch:      branch,
		Language:    language,
		QuerySuite:  querySuite,
		RuleProfile: ruleProfile,
		Rules:       rules,
		Status:      sastModel.TaskStatusPending,
	}

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
	if err := s.db.Model(&sastModel.Vulnerability{}).
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

func (s *ScanService) GetTask(id uint) (*sastModel.ScanTask, error) {
	var task sastModel.ScanTask
	if err := s.db.Preload("Repository").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *ScanService) ListTasks(query *sastModel.ListQuery) (*model.PaginatedResponse, error) {
	query.Page, query.PerPage = model.NormalizePagination(query.Page, query.PerPage)

	db := s.db.Model(&sastModel.ScanTask{})
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

	var tasks []sastModel.ScanTask
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(tasks, total, query.Page, query.PerPage), nil
}

func (s *ScanService) UpdateTaskStatus(taskID uint, status string, updates map[string]interface{}) error {
	if updates == nil {
		updates = map[string]interface{}{}
	}
	updates["status"] = status
	return s.db.Model(&sastModel.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (s *ScanService) AppendTaskLog(taskID uint, message string) error {
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	return s.db.Model(&sastModel.ScanTask{}).
		Where("id = ?", taskID).
		Update("execution_log", gorm.Expr("COALESCE(execution_log, '') || ?", line)).Error
}

func (s *ScanService) SaveResults(repoID, taskID uint, repoURL string, results []contract.Vulnerability) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, result := range results {
			dataFlowJSON, err := json.Marshal(result.DataFlow)
			if err != nil {
				return fmt.Errorf("marshal data flow: %w", err)
			}
			vulnerability := &sastModel.Vulnerability{
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
					"status":       sastModel.VulnStatusNew,
				}).
				FirstOrCreate(vulnerability).Error; err != nil {
				return fmt.Errorf("save vulnerability %s: %w", result.Fingerprint, err)
			}
		}
		return nil
	})
}

func (s *ScanService) ListVulnerabilities(query *sastModel.ListQuery) (*model.PaginatedResponse, error) {
	query.Page, query.PerPage = model.NormalizePagination(query.Page, query.PerPage)

	db := s.db.Model(&sastModel.Vulnerability{})
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

	var vulns []sastModel.Vulnerability
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&vulns).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(vulns, total, query.Page, query.PerPage), nil
}

func (s *ScanService) DeleteTask(taskID uint) error {
	task, err := s.GetTask(taskID)
	if err != nil {
		return err
	}
	if task.Status == sastModel.TaskStatusPending || task.Status == sastModel.TaskStatusRunning {
		return errors.New("cannot delete a pending or running scan task")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("scan_task_id = ?", taskID).Delete(&sastModel.Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Delete(&sastModel.ScanTask{}, taskID).Error; err != nil {
			return err
		}
		return nil
	})
}
