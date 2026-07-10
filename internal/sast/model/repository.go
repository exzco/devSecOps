package model

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Repository struct {
	ID              uint           `json:"id" gorm:"primaryKey"`
	Name            string         `json:"name" gorm:"size:255;not null"`
	URL             string         `json:"url" gorm:"size:512;not null"`
	Branch          string         `json:"branch" gorm:"size:128;default:main"`
	Language        string         `json:"language" gorm:"size:64"`
	Stars           int            `json:"stars" gorm:"default:0;index"`
	Source          string         `json:"source" gorm:"size:64;default:manual"`
	AutoScanEnabled bool           `json:"auto_scan_enabled" gorm:"default:false;index"`
	AuthType        string         `json:"auth_type" gorm:"size:32"` // ssh_key / token / none
	AuthSecret      string         `json:"-" gorm:"type:text"`       // encrypted credential
	ScanConfig      datatypes.JSON `json:"scan_config" gorm:"type:jsonb"`
	WebhookSecret   string         `json:"-" gorm:"size:128"`
	IsActive        bool           `json:"is_active" gorm:"default:true"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `json:"-" gorm:"index"`
}

// ScanConfigData represents the JSON structure for scan configuration
type ScanConfigData struct {
	QuerySuite   string   `json:"query_suite"`
	ExcludePaths []string `json:"exclude_paths"`
	BuildCommand string   `json:"build_command"`
	ExtraArgs    []string `json:"extra_args"`
}

// CreateRepoRequest is the request body for creating a repository
type CreateRepoRequest struct {
	Name            string          `json:"name" binding:"required"`
	URL             string          `json:"url" binding:"required"`
	Branch          string          `json:"branch"`
	Language        string          `json:"language" binding:"required,oneof=go java javascript python"`
	Stars           int             `json:"stars"`
	Source          string          `json:"source"`
	AutoScanEnabled bool            `json:"auto_scan_enabled"`
	AuthType        string          `json:"auth_type" binding:"oneof=ssh_key token none"`
	AuthSecret      string          `json:"auth_secret"`
	ScanConfig      *ScanConfigData `json:"scan_config"`
}

// UpdateRepoRequest is the request body for updating a repository
type UpdateRepoRequest struct {
	Name            *string         `json:"name"`
	URL             *string         `json:"url"`
	Branch          *string         `json:"branch"`
	Language        *string         `json:"language" binding:"omitempty,oneof=go java javascript python"`
	Stars           *int            `json:"stars"`
	Source          *string         `json:"source"`
	AutoScanEnabled *bool           `json:"auto_scan_enabled"`
	AuthType        *string         `json:"auth_type" binding:"omitempty,oneof=ssh_key token none"`
	AuthSecret      *string         `json:"auth_secret"`
	ScanConfig      *ScanConfigData `json:"scan_config"`
	IsActive        *bool           `json:"is_active"`
}

type BatchDeleteReposRequest struct {
	IDs []uint `json:"ids" binding:"required,min=1"`
}
