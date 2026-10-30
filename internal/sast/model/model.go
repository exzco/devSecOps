package model

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	TaskStatusPending  = "pending"
	TaskStatusRunning  = "running"
	TaskStatusSuccess  = "success"
	TaskStatusFailed   = "failed"
	TaskStatusTimeout  = "timeout"
	TaskStatusCanceled = "canceled"

	TriggerTypeManual = "manual"

	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"

	VulnStatusNew           = "new"
	VulnStatusConfirmed     = "confirmed"
	VulnStatusFalsePositive = "false_positive"
	VulnStatusAssigned      = "assigned"
	VulnStatusFixing        = "fixing"
	VulnStatusFixed         = "fixed"
	VulnStatusVerified      = "verified"
)

type Repository struct {
	ID         uint           `json:"id" gorm:"primaryKey"`
	Name       string         `json:"name" gorm:"size:255;not null"`
	URL        string         `json:"url" gorm:"size:512;not null"`
	Branch     string         `json:"branch" gorm:"size:128;default:main"`
	Language   string         `json:"language" gorm:"size:64"`
	AuthType   string         `json:"auth_type" gorm:"size:32"`
	AuthSecret string         `json:"-" gorm:"type:text"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `json:"-" gorm:"index"`
}

// RepoRequest is shared by create and update operations.
type RepoRequest struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Branch     string `json:"branch"`
	Language   string `json:"language" binding:"omitempty,oneof=go java javascript python"`
	AuthType   string `json:"auth_type" binding:"omitempty,oneof=ssh_key token none"`
	AuthSecret string `json:"auth_secret"`
}

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

type Vulnerability struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	ScanTaskID  uint           `json:"scan_task_id" gorm:"index;not null"`
	ScanTask    ScanTask       `json:"scan_task,omitempty" gorm:"foreignKey:ScanTaskID"`
	RepoID      uint           `json:"repo_id" gorm:"index;not null"`
	Repository  Repository     `json:"repository,omitempty" gorm:"foreignKey:RepoID"`
	RepoURL     string         `json:"repo_url" gorm:"size:512;index"`
	RuleID      string         `json:"rule_id" gorm:"size:128;index"`
	RuleName    string         `json:"rule_name" gorm:"size:256"`
	Severity    string         `json:"severity" gorm:"size:32;index"`
	Status      string         `json:"status" gorm:"size:32;default:new;index"`
	FilePath    string         `json:"file_path" gorm:"size:512"`
	StartLine   int            `json:"start_line"`
	EndLine     int            `json:"end_line"`
	CodeSnippet string         `json:"code_snippet" gorm:"type:text"`
	Message     string         `json:"message" gorm:"type:text"`
	DataFlow    datatypes.JSON `json:"data_flow" gorm:"type:jsonb"`
	Fingerprint string         `json:"fingerprint" gorm:"size:256;index"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

// ListQuery is shared by task and vulnerability list endpoints.
type ListQuery struct {
	RepoID   uint   `form:"repo_id"`
	TaskID   uint   `form:"task_id"`
	Status   string `form:"status"`
	Severity string `form:"severity"`
	RuleID   string `form:"rule_id"`
	Page     int    `form:"page,default=1"`
	PerPage  int    `form:"per_page,default=20"`
}
