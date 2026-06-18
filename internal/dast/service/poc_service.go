package service

import (
	"context"

	"gorm.io/gorm"

	"devsecops/internal/model"
)

type PocService struct {
	db *gorm.DB
}

func NewPocService(db *gorm.DB) *PocService {
	return &PocService{db: db}
}

func (s *PocService) CreatePoc(ctx context.Context, poc *model.PocTemplate) error {
	return s.db.WithContext(ctx).Create(poc).Error
}

func (s *PocService) ListPocs(ctx context.Context) ([]model.PocTemplate, error) {
	var pocs []model.PocTemplate
	err := s.db.WithContext(ctx).Order("id desc").Find(&pocs).Error
	return pocs, err
}

func (s *PocService) UpdatePoc(ctx context.Context, poc *model.PocTemplate) error {
	return s.db.WithContext(ctx).Save(poc).Error
}

func (s *PocService) DeletePoc(ctx context.Context, id uint) error {
	return s.db.WithContext(ctx).Delete(&model.PocTemplate{}, id).Error
}
