package model

import (
	"time"

	"gorm.io/gorm"
)

// ==========================================
// 全系统统一常量规范
// ==========================================

// 任务生命周期状态
const (
	TaskStatusPending  = "pending"
	TaskStatusRunning  = "running"
	TaskStatusSuccess  = "success"
	TaskStatusFailed   = "failed"
	TaskStatusTimeout  = "timeout"
	TaskStatusCanceled = "canceled"

	TriggerTypeManual = "manual"
)

// 全系统统一漏洞严重级别
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// 漏洞生命周期流转状态
const (
	VulnStatusNew           = "new"
	VulnStatusConfirmed     = "confirmed"
	VulnStatusFalsePositive = "false_positive"
	VulnStatusAssigned      = "assigned"
	VulnStatusFixing        = "fixing"
	VulnStatusFixed         = "fixed"
	VulnStatusVerified      = "verified"
)

// ==========================================
// 顶层抽象领域模型基类
// ==========================================

// BaseEntity 数据库持久化实体的顶层抽象，包含统一主键与时间戳元数据
type BaseEntity struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`
}

// BaseTask 异步作业与扫描任务的生命周期基类
type BaseTask struct {
	BaseEntity
	Status       string     `json:"status" gorm:"size:32;default:pending;index"`
	StartedAt    *time.Time `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at"`
	DurationMs   int64      `json:"duration_ms"`
	ExecutionLog string     `json:"execution_log,omitempty" gorm:"type:text"`
	VulnCount    int        `json:"vuln_count" gorm:"default:0"`
}

// BaseVulnerability 所有安全发现与漏洞的基础模型
type BaseVulnerability struct {
	RuleID      string `json:"rule_id,omitempty" gorm:"size:128;index"`
	RuleName    string `json:"rule_name,omitempty" gorm:"size:256"`
	Severity    string `json:"severity" gorm:"size:32;index"`
	Status      string `json:"status,omitempty" gorm:"size:32;default:new;index"`
	Title       string `json:"title,omitempty" gorm:"size:512"`
	Description string `json:"description,omitempty" gorm:"type:text"`
	Message     string `json:"message,omitempty" gorm:"type:text"`
}
