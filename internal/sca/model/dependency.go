package model

import (
	"time"

	"gorm.io/gorm"
)

type ScaDependency struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	TaskID    uint           `json:"task_id" gorm:"index;not null"`
	ProjectID uint           `json:"project_id" gorm:"index;not null"`
	Name      string         `json:"name" gorm:"size:256;not null"`
	Version   string         `json:"version" gorm:"size:128;not null"`
	Ecosystem string         `json:"ecosystem" gorm:"size:64;default:Go"` // Go, npm, PyPI, Maven, etc.
	Direct    bool           `json:"direct" gorm:"default:true"`
	Licence   string         `json:"licence" gorm:"size:128"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}
