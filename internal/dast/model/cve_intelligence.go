package model

import (
	"time"

	"gorm.io/gorm"
)

type CveIntelligence struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	CveID       string         `json:"cve_id" gorm:"size:128;uniqueIndex;not null"`
	Component   string         `json:"component" gorm:"size:256"`
	Severity    string         `json:"severity" gorm:"size:32"`
	CvssScore   float64        `json:"cvss_score" gorm:"default:0"`
	Summary     string         `json:"summary" gorm:"type:text"`
	Details     string         `json:"details" gorm:"type:text"`
	PublishedAt string         `json:"published_at" gorm:"size:64;index"`
	HasEXP      bool           `json:"has_exp" gorm:"default:false"`
	ExpURL      string         `json:"exp_url" gorm:"size:512"`
	Tags        string         `json:"tags" gorm:"type:text"` // Comma-separated or JSON
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}
