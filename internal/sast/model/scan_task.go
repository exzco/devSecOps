package model

import (
	"time"

	"gorm.io/gorm"
)

// Task status constants
const (
	TaskStatusPending  = "pending"
	TaskStatusRunning  = "running"
	TaskStatusSuccess  = "success"
	TaskStatusFailed   = "failed"
	TaskStatusTimeout  = "timeout"
	TaskStatusCanceled = "canceled"
)

// Trigger type constants
const (
	TriggerTypeManual  = "manual"
	TriggerTypeWebhook = "webhook"
	TriggerTypeCron    = "cron"
)

type ScanTask struct {
	ID           uint           `json:"id" gorm:"primaryKey"`
	RepoID       uint           `json:"repo_id" gorm:"index;not null"`
	Repository   Repository     `json:"repository,omitempty" gorm:"foreignKey:RepoID"`
	TriggerType  string         `json:"trigger_type" gorm:"size:32"`
	Branch       string         `json:"branch" gorm:"size:128"`
	CommitSHA    string         `json:"commit_sha" gorm:"size:64"`
	Status       string         `json:"status" gorm:"size:32;default:pending;index"`
	Language     string         `json:"language" gorm:"size:64"`
	QuerySuite   string         `json:"query_suite" gorm:"size:512"`
	RuleProfile  string         `json:"rule_profile" gorm:"size:128"`
	Rules        string         `json:"rules" gorm:"type:text"`
	StartedAt    *time.Time     `json:"started_at"`
	FinishedAt   *time.Time     `json:"finished_at"`
	DurationMs   int64          `json:"duration_ms"`
	ErrorMsg     string         `json:"error_msg" gorm:"type:text"`
	ExecutionLog string         `json:"execution_log" gorm:"type:text"`
	SARIFPath    string         `json:"sarif_path" gorm:"size:512"`
	WorkerID     string         `json:"worker_id" gorm:"size:128"`
	VulnCount    int            `json:"vuln_count" gorm:"default:0"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`
}

// CreateScanRequest is the request body for manually triggering a scan
type CreateScanRequest struct {
	RepoID      uint     `json:"repo_id" binding:"required"`
	Branch      string   `json:"branch" binding:"required"`
	Language    string   `json:"language" binding:"required"`
	QuerySuite  string   `json:"query_suite"`
	RuleProfile string   `json:"rule_profile"`
	Rules       []string `json:"rules"`
}

// ScanTaskQuery contains query parameters for listing scan tasks
type ScanTaskQuery struct {
	RepoID  uint   `form:"repo_id"`
	Status  string `form:"status"`
	Page    int    `form:"page,default=1"`
	PerPage int    `form:"per_page,default=20"`
}
