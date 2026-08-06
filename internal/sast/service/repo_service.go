package service

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"gorm.io/gorm"

	"devsecops/internal/model"
	"devsecops/internal/sast/async"
	sastModel "devsecops/internal/sast/model"
)

type RepoService struct {
	db *gorm.DB
}

func NewRepoService(db *gorm.DB) *RepoService {
	return &RepoService{db: db}
}

func (s *RepoService) Create(req *sastModel.CreateRepoRequest) (*sastModel.Repository, error) {
	if req.AutoScanEnabled {
		return nil, fmt.Errorf("定时扫描功能已取消，暂不支持开启自动扫描")
	}
	repo := &sastModel.Repository{
		Name:            req.Name,
		URL:             req.URL,
		Branch:          req.Branch,
		Language:        req.Language,
		Stars:           req.Stars,
		Source:          req.Source,
		AutoScanEnabled: false,
		AuthType:        req.AuthType,
		AuthSecret:      req.AuthSecret,
		IsActive:        true,
	}

	if repo.Branch == "" {
		repo.Branch = "main"
	}
	if repo.AuthType == "" {
		repo.AuthType = "none"
	}
	if strings.TrimSpace(repo.Source) == "" {
		repo.Source = "manual"
	}

	if req.ScanConfig != nil {
		configJSON, err := json.Marshal(req.ScanConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal scan config: %w", err)
		}
		repo.ScanConfig = configJSON
	}

	if err := s.db.Create(repo).Error; err != nil {
		return nil, err
	}
	return repo, nil
}

func (s *RepoService) GetByID(id uint) (*sastModel.Repository, error) {
	var repo sastModel.Repository
	if err := s.db.First(&repo, id).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *RepoService) GetByURL(url string) (*sastModel.Repository, error) {
	var repo sastModel.Repository
	err := s.db.Where("url = ?", strings.TrimSpace(url)).First(&repo).Error
	if err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *RepoService) List(page, perPage int) (*model.PaginatedResponse, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	var repos []sastModel.Repository
	var total int64

	s.db.Model(&sastModel.Repository{}).Count(&total)
	offset := (page - 1) * perPage
	if err := s.db.Order("id DESC").Offset(offset).Limit(perPage).Find(&repos).Error; err != nil {
		return nil, err
	}

	return &model.PaginatedResponse{
		Data:       repos,
		Total:      total,
		Page:       page,
		PerPage:    perPage,
		TotalPages: int(math.Ceil(float64(total) / float64(perPage))),
	}, nil
}

func (s *RepoService) Update(id uint, req *sastModel.UpdateRepoRequest) (*sastModel.Repository, error) {
	repo, err := s.GetByID(id)
	if err != nil {
		return nil, err
	}
	if req.AutoScanEnabled != nil && *req.AutoScanEnabled {
		return nil, fmt.Errorf("定时扫描功能已取消，暂不支持开启自动扫描")
	}

	updates := map[string]interface{}{}
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.URL != nil {
		updates["url"] = *req.URL
	}
	if req.Branch != nil {
		updates["branch"] = *req.Branch
	}
	if req.Language != nil {
		updates["language"] = *req.Language
	}
	if req.Stars != nil {
		updates["stars"] = *req.Stars
	}
	if req.Source != nil {
		updates["source"] = *req.Source
	}
	updates["auto_scan_enabled"] = false
	if req.AuthType != nil {
		updates["auth_type"] = *req.AuthType
	}
	if req.AuthSecret != nil && *req.AuthSecret != "" {
		updates["auth_secret"] = *req.AuthSecret
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}
	if req.ScanConfig != nil {
		configJSON, err := json.Marshal(req.ScanConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal scan config: %w", err)
		}
		updates["scan_config"] = configJSON
	}

	if err := s.db.Model(repo).Updates(updates).Error; err != nil {
		return nil, err
	}

	return s.GetByID(id)
}

func (s *RepoService) Delete(id uint) error {
	// 1. 主动终止该仓库旗下所有处于排队或运行中的扫描任务
	var activeTaskIDs []uint
	s.db.Model(&sastModel.ScanTask{}).
		Where("repo_id = ? AND status IN ?", id, []string{string(sastModel.TaskStatusPending), string(sastModel.TaskStatusRunning)}).
		Pluck("id", &activeTaskIDs)

	for _, taskID := range activeTaskIDs {
		async.CancelTask(taskID)
	}

	// 2. 数据库事务中清理数据
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("repo_id = ?", id).Delete(&sastModel.Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("repo_id = ?", id).Delete(&sastModel.ScanTask{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Delete(&sastModel.Repository{}, id).Error; err != nil {
			return err
		}
		return nil
	})
}

func (s *RepoService) DeleteBatch(ids []uint) error {
	if len(ids) == 0 {
		return nil
	}

	// 1. 批量主动终止所有相关仓库正在运行或排队中的扫描任务
	var activeTaskIDs []uint
	s.db.Model(&sastModel.ScanTask{}).
		Where("repo_id IN ? AND status IN ?", ids, []string{string(sastModel.TaskStatusPending), string(sastModel.TaskStatusRunning)}).
		Pluck("id", &activeTaskIDs)

	for _, taskID := range activeTaskIDs {
		async.CancelTask(taskID)
	}

	// 2. 数据库事务中清理数据
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Where("repo_id IN ?", ids).Delete(&sastModel.Vulnerability{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("repo_id IN ?", ids).Delete(&sastModel.ScanTask{}).Error; err != nil {
			return err
		}
		if err := tx.Unscoped().Where("id IN ?", ids).Delete(&sastModel.Repository{}).Error; err != nil {
			return err
		}
		return nil
	})
}
