package model

// ScaScanTask SCA 任务记录，继承 BaseTask
type ScaScanTask struct {
	BaseTask
	RepoID        uint   `json:"repo_id" gorm:"index"`
	TargetDir     string `json:"target_dir" gorm:"size:512"`
	Branch        string `json:"branch" gorm:"size:128;default:main"`
	Language      string `json:"language" gorm:"size:64;default:auto"`
	TotalDeps     int    `json:"total_deps" gorm:"default:0"`
	CriticalCount int    `json:"critical_count" gorm:"default:0"`
	HighCount     int    `json:"high_count" gorm:"default:0"`
	MediumCount   int    `json:"medium_count" gorm:"default:0"`
	LowCount      int    `json:"low_count" gorm:"default:0"`
	InfoCount     int    `json:"info_count" gorm:"default:0"`
	ErrorMessage  string `json:"error_message,omitempty" gorm:"type:text"`
}

// ScaDependency SCA 依赖项明细，继承 BaseEntity
type ScaDependency struct {
	BaseEntity
	TaskID    uint   `json:"task_id" gorm:"index;not null"`
	RepoID    uint   `json:"repo_id" gorm:"index"`
	Name      string `json:"name" gorm:"size:256;not null;index"`
	Version   string `json:"version" gorm:"size:128;not null"`
	Ecosystem string `json:"ecosystem" gorm:"size:64;not null;index"` // Go, PyPI, Maven, npm, crates.io
	Direct    bool   `json:"direct" gorm:"default:true"`
	License   string `json:"license" gorm:"size:128"`
	FilePath  string `json:"file_path" gorm:"size:512"`
	VulnCount int    `json:"vuln_count" gorm:"default:0"`
}

// ScaVulnerability SCA 漏洞记录，继承 BaseEntity 与 BaseVulnerability
type ScaVulnerability struct {
	BaseEntity
	BaseVulnerability
	TaskID         uint   `json:"task_id" gorm:"index;not null"`
	RepoID         uint   `json:"repo_id" gorm:"index"`
	DependencyID   uint   `json:"dependency_id" gorm:"index;not null"`
	DependencyName string `json:"dependency_name" gorm:"size:256;index"`
	CurrentVersion string `json:"current_version" gorm:"size:128"`
	Ecosystem      string `json:"ecosystem" gorm:"size:64;index"`
	VulnID         string `json:"vuln_id" gorm:"size:128;index;not null"` // e.g. GHSA-xxx or CVE-xxx
	Aliases        string `json:"aliases" gorm:"size:512;index"`          // e.g. CVE-2023-xxxx
	Summary        string `json:"summary" gorm:"type:text"`
	Details        string `json:"details" gorm:"type:text"`
	FixedVersion   string `json:"fixed_version" gorm:"size:128"`
	References     string `json:"references" gorm:"type:text"`
}

// CreateScaTaskRequest 发起 SCA 分析的请求载荷
type CreateScaTaskRequest struct {
	RepoID   uint   `json:"repo_id"`
	Branch   string `json:"branch"`
	Language string `json:"language"`
	Target   string `json:"target"`
}
