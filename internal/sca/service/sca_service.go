package service

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	scaModel "devsecops/internal/sca/model"
)

type ScaService struct {
	db *gorm.DB
}

func NewScaService(db *gorm.DB) *ScaService {
	return &ScaService{db: db}
}

// --- Project Management ---

func (s *ScaService) CreateProject(ctx context.Context, req *scaModel.CreateScaProjectRequest) (*scaModel.ScaProject, error) {
	branch := req.Branch
	if branch == "" {
		branch = "main"
	}
	lang := req.Language
	if lang == "" {
		lang = "go"
	}

	proj := &scaModel.ScaProject{
		Name:        req.Name,
		GitURL:      req.GitURL,
		Branch:      branch,
		Language:    lang,
		Description: req.Description,
	}

	if err := s.db.WithContext(ctx).Create(proj).Error; err != nil {
		return nil, fmt.Errorf("create sca project: %w", err)
	}

	return proj, nil
}

func (s *ScaService) ListProjects(ctx context.Context, page, perPage int) ([]scaModel.ScaProject, int64, error) {
	var projects []scaModel.ScaProject
	var total int64

	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 20
	}

	db := s.db.WithContext(ctx).Model(&scaModel.ScaProject{})
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	if err := db.Order("id desc").Offset(offset).Limit(perPage).Find(&projects).Error; err != nil {
		return nil, 0, err
	}

	return projects, total, nil
}

func (s *ScaService) DeleteProject(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Delete(&scaModel.ScaProject{}, id).Error
}

// --- Task & Vulnerability Management ---

func (s *ScaService) CreateScanTask(ctx context.Context, projectID uint) (*scaModel.ScaScanTask, error) {
	var proj scaModel.ScaProject
	if err := s.db.WithContext(ctx).First(&proj, projectID).Error; err != nil {
		return nil, fmt.Errorf("project not found: %w", err)
	}

	now := time.Now()
	task := &scaModel.ScaScanTask{
		ProjectID: projectID,
		Status:    "success", // Simulating sync completion
		StartedAt: &now,
	}

	if err := s.db.WithContext(ctx).Create(task).Error; err != nil {
		return nil, err
	}

	// Update project last scan status
	proj.LastScanAt = &now
	proj.LastScanStatus = "success"
	_ = s.db.WithContext(ctx).Save(&proj).Error

	return task, nil
}

func (s *ScaService) ListTasks(ctx context.Context, page, perPage int, projectID uint) ([]scaModel.ScaScanTask, int64, error) {
	var tasks []scaModel.ScaScanTask
	var total int64

	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 20
	}

	db := s.db.WithContext(ctx).Model(&scaModel.ScaScanTask{})
	if projectID > 0 {
		db = db.Where("project_id = ?", projectID)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	if err := db.Preload("Project").Order("id desc").Offset(offset).Limit(perPage).Find(&tasks).Error; err != nil {
		return nil, 0, err
	}

	return tasks, total, nil
}

func (s *ScaService) ListDependencies(ctx context.Context, projectID uint) ([]scaModel.ScaDependency, error) {
	var deps []scaModel.ScaDependency
	db := s.db.WithContext(ctx).Model(&scaModel.ScaDependency{})
	if projectID > 0 {
		db = db.Where("project_id = ?", projectID)
	}
	err := db.Order("name asc").Find(&deps).Error
	return deps, err
}

func (s *ScaService) ListVulnerabilities(ctx context.Context, page, perPage int, projectID uint) ([]scaModel.ScaVulnerability, int64, error) {
	var vulns []scaModel.ScaVulnerability
	var total int64

	if page <= 0 {
		page = 1
	}
	if perPage <= 0 {
		perPage = 20
	}

	db := s.db.WithContext(ctx).Model(&scaModel.ScaVulnerability{})
	if projectID > 0 {
		db = db.Where("project_id = ?", projectID)
	}

	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * perPage
	if err := db.Order("id desc").Offset(offset).Limit(perPage).Find(&vulns).Error; err != nil {
		return nil, 0, err
	}

	return vulns, total, nil
}
