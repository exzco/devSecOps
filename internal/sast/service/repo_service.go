package service

import (
	"gorm.io/gorm"

	"devsecops/internal/model"
	sastModel "devsecops/internal/sast/model"
)

type RepoService struct {
	db *gorm.DB
}

func NewRepoService(db *gorm.DB) *RepoService {
	return &RepoService{db: db}
}

func (s *RepoService) Create(req *sastModel.RepoRequest) (*sastModel.Repository, error) {
	repo := &sastModel.Repository{
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

func (s *RepoService) GetByID(id uint) (*sastModel.Repository, error) {
	var repo sastModel.Repository
	if err := s.db.First(&repo, id).Error; err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *RepoService) List(page, perPage int) (*model.PaginatedResponse, error) {
	page, perPage = model.NormalizePagination(page, perPage)

	var repos []sastModel.Repository
	var total int64

	if err := s.db.Model(&sastModel.Repository{}).Count(&total).Error; err != nil {
		return nil, err
	}
	offset := (page - 1) * perPage
	if err := s.db.Order("id DESC").Offset(offset).Limit(perPage).Find(&repos).Error; err != nil {
		return nil, err
	}

	return model.NewPaginatedResponse(repos, total, page, perPage), nil
}

func (s *RepoService) Update(id uint, req *sastModel.RepoRequest) (*sastModel.Repository, error) {
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
