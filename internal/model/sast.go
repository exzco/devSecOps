package model

import (
	"gorm.io/datatypes"
)

// Repository 被测代码仓库模型
type Repository struct {
	BaseEntity
	Name       string `json:"name" gorm:"size:255;not null"`
	URL        string `json:"url" gorm:"size:512;not null"`
	Branch     string `json:"branch" gorm:"size:128;default:main"`
	Language   string `json:"language" gorm:"size:64"`
	AuthType   string `json:"auth_type" gorm:"size:32"`
	AuthSecret string `json:"-" gorm:"type:text"`
}

// RepoRequest 仓库创建与更新请求载荷
type RepoRequest struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Branch     string `json:"branch"`
	Language   string `json:"language" binding:"omitempty,oneof=go java javascript python"`
	AuthType   string `json:"auth_type" binding:"omitempty,oneof=ssh_key token none"`
	AuthSecret string `json:"auth_secret"`
}

// ScanTask SAST 静态代码扫描任务记录，继承 BaseTask
type ScanTask struct {
	BaseTask
	RepoID      uint       `json:"repo_id" gorm:"index;not null"`
	Repository  Repository `json:"repository,omitempty" gorm:"foreignKey:RepoID"`
	TriggerType string     `json:"trigger_type" gorm:"size:32"`
	Branch      string     `json:"branch" gorm:"size:128"`
	CommitSHA   string     `json:"commit_sha" gorm:"size:64"`
	Language    string     `json:"language" gorm:"size:64"`
	QuerySuite  string     `json:"query_suite" gorm:"size:512"`
	RuleProfile string     `json:"rule_profile" gorm:"size:128"`
	Rules       string     `json:"rules" gorm:"type:text"`
	ErrorMsg    string     `json:"error_msg,omitempty" gorm:"type:text"`
	SARIFPath   string     `json:"sarif_path" gorm:"size:512"`
	WorkerID    string     `json:"worker_id" gorm:"size:128"`
}

// Vulnerability SAST 扫描发现的代码漏洞记录，继承 BaseEntity 与 BaseVulnerability
type Vulnerability struct {
	BaseEntity
	BaseVulnerability
	ScanTaskID  uint           `json:"scan_task_id" gorm:"index;not null"`
	ScanTask    ScanTask       `json:"scan_task,omitempty" gorm:"foreignKey:ScanTaskID"`
	RepoID      uint           `json:"repo_id" gorm:"index;not null"`
	Repository  Repository     `json:"repository,omitempty" gorm:"foreignKey:RepoID"`
	RepoURL     string         `json:"repo_url" gorm:"size:512;index"`
	FilePath    string         `json:"file_path" gorm:"size:512"`
	StartLine   int            `json:"start_line"`
	EndLine     int            `json:"end_line"`
	CodeSnippet string         `json:"code_snippet" gorm:"type:text"`
	DataFlow    datatypes.JSON `json:"data_flow" gorm:"type:jsonb"`
	Fingerprint string         `json:"fingerprint" gorm:"size:256;index"`
}

// FlowStep 污点追踪数据流步进节点
type FlowStep struct {
	FilePath  string `json:"file_path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Message   string `json:"message"`
	Snippet   string `json:"snippet"`
}
