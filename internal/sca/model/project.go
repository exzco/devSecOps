package model

import (
	"time"

	"gorm.io/gorm"
)

type ScaProject struct {
	ID                 uint           `json:"id" gorm:"primaryKey"`
	Name               string         `json:"name" gorm:"size:256;not null"`
	GitURL             string         `json:"git_url" gorm:"size:512;not null"`
	Branch             string         `json:"branch" gorm:"size:128;default:main"`
	Language           string         `json:"language" gorm:"size:64;default:go"`
	Description        string         `json:"description" gorm:"type:text"`
	LastScanAt         *time.Time     `json:"last_scan_at"`
	LastScanStatus     string         `json:"last_scan_status" gorm:"size:32;default:unscanned"` // unscanned, running, success, failed
	VulnerabilityCount int            `json:"vulnerability_count" gorm:"default:0"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	DeletedAt          gorm.DeletedAt `json:"-" gorm:"index"`
}

type CreateScaProjectRequest struct {
	Name        string `json:"name" binding:"required"`
	GitURL      string `json:"git_url" binding:"required"`
	Branch      string `json:"branch"`
	Language    string `json:"language"`
	Description string `json:"description"`
}

type UpdateScaProjectRequest struct {
	Name        string `json:"name"`
	GitURL      string `json:"git_url"`
	Branch      string `json:"branch"`
	Language    string `json:"language"`
	Description string `json:"description"`
}
