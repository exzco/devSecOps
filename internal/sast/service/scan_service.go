package service

import (
	"encoding/json"
	"fmt"
	"math"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/model"
	sastModel "devsecops/internal/sast/model"
	"devsecops/internal/sast/scanner"
)

type ScanService struct {
	db     *gorm.DB
	worker *scanner.ScanWorker
}

func NewScanService(db *gorm.DB, worker *scanner.ScanWorker) *ScanService {
	return &ScanService{db: db, worker: worker}
}

func (s *ScanService) GetDB() *gorm.DB {
	return s.db
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

func (s *ScanService) GetTask(id uint) (*sastModel.ScanTask, error) {
	var task sastModel.ScanTask
	if err := s.db.Preload("Repository").First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *ScanService) ListTasks(query *sastModel.ScanTaskQuery) (*model.PaginatedResponse, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PerPage < 1 || query.PerPage > 100 {
		query.PerPage = 20
	}

	db := s.db.Model(&sastModel.ScanTask{})
	if query.RepoID > 0 {
		db = db.Where("repo_id = ?", query.RepoID)
	}
	if query.Status != "" {
		db = db.Where("status = ?", query.Status)
	}

	var total int64
	db.Count(&total)

	var tasks []sastModel.ScanTask
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&tasks).Error; err != nil {
		return nil, err
	}

	return &model.PaginatedResponse{
		Data:       tasks,
		Total:      total,
		Page:       query.Page,
		PerPage:    query.PerPage,
		TotalPages: int(math.Ceil(float64(total) / float64(query.PerPage))),
	}, nil
}

func (s *ScanService) UpdateTaskStatus(taskID uint, status string, updates map[string]interface{}) error {
	if updates == nil {
		updates = map[string]interface{}{}
	}
	updates["status"] = status
	return s.db.Model(&sastModel.ScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func (s *ScanService) SaveVulnerabilities(taskID, repoID uint, parsed []scanner.ParsedVulnerability) (int, error) {
	saved := 0
	repoURL := ""
	var repo sastModel.Repository
	if err := s.db.Select("url").First(&repo, repoID).Error; err == nil {
		repoURL = repo.URL
	}
	for _, p := range parsed {
		dataFlowJSON, _ := json.Marshal(p.DataFlow)

		vuln := &sastModel.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			RepoURL:     repoURL,
			RuleID:      p.RuleID,
			RuleName:    p.RuleName,
			Severity:    p.Severity,
			Status:      sastModel.VulnStatusNew,
			FilePath:    p.FilePath,
			StartLine:   p.StartLine,
			EndLine:     p.EndLine,
			CodeSnippet: p.CodeSnippet,
			Message:     p.Message,
			DataFlow:    datatypes.JSON(dataFlowJSON),
			Fingerprint: p.Fingerprint,
		}

		result := s.db.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
			Assign(map[string]interface{}{
				"scan_task_id": taskID,
				"repo_url":     repoURL,
				"code_snippet": p.CodeSnippet,
				"message":      p.Message,
				"data_flow":    datatypes.JSON(dataFlowJSON),
			}).
			FirstOrCreate(vuln)

		if result.Error != nil {
			return saved, fmt.Errorf("failed to save vulnerability: %w", result.Error)
		}
		saved++
	}

	s.db.Model(&sastModel.ScanTask{}).Where("id = ?", taskID).Update("vuln_count", saved)

	return saved, nil
}

func (s *ScanService) ListVulnerabilities(query *sastModel.VulnQuery) (*model.PaginatedResponse, error) {
	if query.Page < 1 {
		query.Page = 1
	}
	if query.PerPage < 1 || query.PerPage > 100 {
		query.PerPage = 20
	}

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
	db.Count(&total)

	var vulns []sastModel.Vulnerability
	offset := (query.Page - 1) * query.PerPage
	if err := db.Preload("Repository").Order("id DESC").Offset(offset).Limit(query.PerPage).Find(&vulns).Error; err != nil {
		return nil, err
	}

	return &model.PaginatedResponse{
		Data:       vulns,
		Total:      total,
		Page:       query.Page,
		PerPage:    query.PerPage,
		TotalPages: int(math.Ceil(float64(total) / float64(query.PerPage))),
	}, nil
}

func (s *ScanService) GetVulnerability(id uint) (*sastModel.Vulnerability, error) {
	var vuln sastModel.Vulnerability
	if err := s.db.Preload("Repository").Preload("ScanTask").Preload("Assignee").First(&vuln, id).Error; err != nil {
		return nil, err
	}
	return &vuln, nil
}

// ActiveTaskCanceler registry to be set by scheduler package to break import cycle
var ActiveTaskCanceler func(taskID uint)

func (s *ScanService) DeleteTask(taskID uint) error {
	// Cancel the task if it is currently running (notified via callback to break import cycle)
	if ActiveTaskCanceler != nil {
		ActiveTaskCanceler(taskID)
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

func (s *ScanService) UpdateVulnStatus(vulnID, operatorID uint, req *sastModel.UpdateVulnStatusRequest) error {
	vuln, err := s.GetVulnerability(vulnID)
	if err != nil {
		return err
	}

	oldStatus := vuln.Status
	if err := s.db.Model(vuln).Update("status", req.Status).Error; err != nil {
		return err
	}
	log := &model.AuditLog{
		VulnerabilityID: vulnID,
		OperatorID:      operatorID,
		Action:          "status_change",
		OldStatus:       oldStatus,
		NewStatus:       req.Status,
		Comment:         req.Comment,
	}
	return s.db.Create(log).Error
}

func (s *ScanService) IsDuplicateTask(repoID uint, commitSHA string) bool {
	if commitSHA == "" {
		return false
	}
	var count int64
	s.db.Model(&sastModel.ScanTask{}).
		Where("repo_id = ? AND commit_sha = ? AND status IN ?", repoID, commitSHA, []string{sastModel.TaskStatusPending, sastModel.TaskStatusRunning}).
		Count(&count)
	return count > 0
}

func (s *ScanService) SaveScanResults(repoID, taskID uint, results []scanner.ParsedVulnerability) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		repoURL := ""
		var repo sastModel.Repository
		if err := tx.Select("url").First(&repo, repoID).Error; err == nil {
			repoURL = repo.URL
		}

		for _, p := range results {
			vuln := &sastModel.Vulnerability{
				ScanTaskID:  taskID,
				RepoID:      repoID,
				RepoURL:     repoURL,
				Fingerprint: p.Fingerprint,
			}

			result := tx.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
				Assign(map[string]interface{}{
					"repo_id":      repoID,
					"repo_url":     repoURL,
					"scan_task_id": taskID,
					"file_path":    p.FilePath,
					"start_line":   p.StartLine,
					"end_line":     p.EndLine,
					"message":      p.Message,
					"severity":     p.Severity,
					"rule_id":      p.RuleID,
					"rule_name":    p.RuleName,
					"code_snippet": p.CodeSnippet,
					"fingerprint":  p.Fingerprint,
					"status":       sastModel.VulnStatusNew,
				}).
				FirstOrCreate(vuln)

			if result.Error != nil {
				return fmt.Errorf("保存漏洞失败(rule=%s, file=%s, line=%d): %w", p.RuleID, p.FilePath, p.StartLine, result.Error)
			}
		}
		return nil
	})
}
