package service

import (
	"math"

	"gorm.io/gorm"

	"devsecops/internal/model"
	sastModel "devsecops/internal/sast/model"
)

type ScanService struct {
	db *gorm.DB
}

func NewScanService(db *gorm.DB) *ScanService {
	return &ScanService{db: db}
}

func (s *ScanService) CreateTask(repoID uint, triggerType, branch, language, querySuite, ruleProfile, rules string, useAIVerification bool) (*sastModel.ScanTask, error) {
	task := &sastModel.ScanTask{
		RepoID:            repoID,
		TriggerType:       triggerType,
		Branch:            branch,
		Language:          language,
		QuerySuite:        querySuite,
		RuleProfile:       ruleProfile,
		Rules:             rules,
		UseAIVerification: useAIVerification,
		Status:            sastModel.TaskStatusPending,
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

func (s *ScanService) DeleteTask(taskID uint) error {
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
