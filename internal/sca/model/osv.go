package model

import (
	"time"

	"gorm.io/gorm"
)

// ScaOsvVulnerability 本地 OSV 离线漏洞情报表
type ScaOsvVulnerability struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	VulnID         string         `json:"vuln_id" gorm:"size:128;index;not null"`  // e.g. GHSA-xxxx or GO-2024-xxxx
	Aliases        string         `json:"aliases" gorm:"size:256;index"`           // e.g. CVE-2023-xxxx
	Ecosystem      string         `json:"ecosystem" gorm:"size:64;index;not null"` // Go, npm, PyPI, Maven
	PackageName    string         `json:"package_name" gorm:"size:256;index;not null"`
	Severity       string         `json:"severity" gorm:"size:32"` // CRITICAL, HIGH, MODERATE, LOW
	Summary        string         `json:"summary" gorm:"type:text"`
	Details        string         `json:"details" gorm:"type:text"`
	FixedVersion   string         `json:"fixed_version" gorm:"size:128"`
	AffectedRanges string         `json:"affected_ranges" gorm:"type:text"` // JSON 储存受影响版本表达式或版本列表
	References     string         `json:"references" gorm:"type:text"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}
