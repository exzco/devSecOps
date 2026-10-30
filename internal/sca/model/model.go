package model

import (
	"time"

	"gorm.io/gorm"
)

const (
	TaskStatusPending  = "pending"
	TaskStatusRunning  = "running"
	TaskStatusSuccess  = "success"
	TaskStatusFailed   = "failed"
	TaskStatusCanceled = "canceled"

	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// ScaScanTask represents a software composition analysis task
type ScaScanTask struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	RepoID         uint           `json:"repo_id" gorm:"index"`
	TargetDir      string         `json:"target_dir" gorm:"size:512"`
	Branch         string         `json:"branch" gorm:"size:128;default:main"`
	Language       string         `json:"language" gorm:"size:64;default:auto"`
	Status         string         `json:"status" gorm:"size:32;default:pending;index"`
	TotalDeps      int            `json:"total_deps" gorm:"default:0"`
	VulnCount      int            `json:"vuln_count" gorm:"default:0"`
	CriticalCount  int            `json:"critical_count" gorm:"default:0"`
	HighCount      int            `json:"high_count" gorm:"default:0"`
	MediumCount    int            `json:"medium_count" gorm:"default:0"`
	LowCount       int            `json:"low_count" gorm:"default:0"`
	InfoCount      int            `json:"info_count" gorm:"default:0"`
	ErrorMessage   string         `json:"error_message" gorm:"type:text"`
	ExecutionLog   string         `json:"execution_log" gorm:"type:text"`
	StartedAt      *time.Time     `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at"`
	DurationMs     int64          `json:"duration_ms"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}

// ScaDependency represents a discovered software component / package
type ScaDependency struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	TaskID    uint           `json:"task_id" gorm:"index;not null"`
	RepoID    uint           `json:"repo_id" gorm:"index"`
	Name      string         `json:"name" gorm:"size:256;not null;index"`
	Version   string         `json:"version" gorm:"size:128;not null"`
	Ecosystem string         `json:"ecosystem" gorm:"size:64;not null;index"` // Go, PyPI, Maven, npm, crates.io
	Direct    bool           `json:"direct" gorm:"default:true"`
	License   string         `json:"license" gorm:"size:128"`
	FilePath  string         `json:"file_path" gorm:"size:512"`
	VulnCount int            `json:"vuln_count" gorm:"default:0"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// ScaVulnerability represents a vulnerability associated with a component
type ScaVulnerability struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	TaskID         uint           `json:"task_id" gorm:"index;not null"`
	RepoID         uint           `json:"repo_id" gorm:"index"`
	DependencyID   uint           `json:"dependency_id" gorm:"index;not null"`
	DependencyName string         `json:"dependency_name" gorm:"size:256;index"`
	CurrentVersion string         `json:"current_version" gorm:"size:128"`
	Ecosystem      string         `json:"ecosystem" gorm:"size:64;index"`
	VulnID         string         `json:"vuln_id" gorm:"size:128;index;not null"` // e.g. GHSA-xxx or CVE-xxx
	Aliases        string         `json:"aliases" gorm:"size:512;index"`          // e.g. CVE-2023-xxxx
	Severity       string         `json:"severity" gorm:"size:32;index"`          // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title          string         `json:"title" gorm:"size:512"`
	Summary        string         `json:"summary" gorm:"type:text"`
	Details        string         `json:"details" gorm:"type:text"`
	FixedVersion   string         `json:"fixed_version" gorm:"size:128"`
	References     string         `json:"references" gorm:"type:text"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}

// CreateTaskRequest DTO for initiating an SCA scan
type CreateTaskRequest struct {
	RepoID   uint   `json:"repo_id"`
	Branch   string `json:"branch"`
	Language string `json:"language"`
	Target   string `json:"target"`
}
