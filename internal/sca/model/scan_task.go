package model

import (
	"time"

	"gorm.io/gorm"
)

type ScaScanTask struct {
	ID                uint           `json:"id" gorm:"primaryKey"`
	ProjectID         uint           `json:"project_id" gorm:"index;not null"`
	Project           *ScaProject    `json:"project,omitempty" gorm:"foreignKey:ProjectID"`
	Status            string         `json:"status" gorm:"size:32;default:pending"` // pending, running, success, failed
	TotalDependencies int            `json:"total_dependencies" gorm:"default:0"`
	VulnerableCount   int            `json:"vulnerable_count" gorm:"default:0"`
	ErrorMessage      string         `json:"error_message" gorm:"type:text"`
	StartedAt         *time.Time     `json:"started_at"`
	CompletedAt       *time.Time     `json:"completed_at"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `json:"-" gorm:"index"`
}

type CreateScaScanTaskRequest struct {
	ProjectID uint `json:"project_id" binding:"required"`
}
