package worker

import (
	"time"
)

// Worker 状态常量
const (
	StatusOnline  = "online"
	StatusBusy    = "busy"
	StatusOffline = "offline"

	TypeSAST = "sast"
	TypeDAST = "dast"
)

// DependencyStatus 代表单一外部环境依赖的健康诊断项
type DependencyStatus struct {
	Name        string `json:"name"`        // 依赖名称，如 "CodeQL CLI", "Java JDK", "Git CLI", "PoC 规则库"
	Required    bool   `json:"required"`    // 是否为核心强依赖（强依赖缺失会导致 Worker 无法工作）
	Installed   bool   `json:"installed"`   // 是否已安装/就绪
	Path        string `json:"path"`        // 检测到的二进制或资源路径
	Version     string `json:"version"`     // 检测到的版本字符串 (如 "2.27.3", "git 2.43.0")
	Message     string `json:"message"`     // 状态详情、缺失原因或排查引导
}

// SystemInfo 宿主机基础硬件与系统环境
type SystemInfo struct {
	OS          string `json:"os"`           // linux, darwin, windows
	Arch        string `json:"arch"`         // amd64, arm64
	NumCPU      int    `json:"num_cpu"`      // CPU 核心数
	GoVersion   string `json:"go_version"`   // Go 编译运行版本
	WorkDir     string `json:"work_dir"`     // Worker 工作目录
}

// WorkerInfo Worker 节点全量心跳模型
type WorkerInfo struct {
	ID              string             `json:"id"`                // 唯一标识，如 sast-wshlavery-268952
	Type            string             `json:"type"`              // sast 或 dast
	Hostname        string             `json:"hostname"`          // 宿主机名称
	IP              string             `json:"ip"`                // 节点 IP 地址
	PID             int                `json:"pid"`               // 进程 PID
	Status          string             `json:"status"`            // online, busy, offline
	Ready           bool               `json:"ready"`             // 是否具备合适的工作环境（强依赖全部满足）
	StartedAt       time.Time          `json:"started_at"`        // 启动时间
	LastHeartbeat   time.Time          `json:"last_heartbeat"`    // 最后心跳时间戳
	ActiveTasks     int                `json:"active_tasks"`      // 当前并发执行任务数
	SystemInfo      SystemInfo         `json:"system_info"`       // 宿主机硬件信息
	Dependencies    []DependencyStatus `json:"dependencies"`      // 环境依赖自检明细
	MissingSummary  []string           `json:"missing_summary"`   // 缺失的依赖简要汇总列表
}

// WorkersOverview Server 控制看板聚合输出模型
type WorkersOverview struct {
	TotalWorkers        int          `json:"total_workers"`        // 注册节点总数
	OnlineWorkers       int          `json:"online_workers"`       // 当前存活节点数
	SastOnline          int          `json:"sast_online"`          // SAST 在线节点数
	DastOnline          int          `json:"dast_online"`          // DAST 在线节点数
	AllReady            bool         `json:"all_ready"`            // 所有存活节点是否都具备完整工作环境
	HasMissingDeps      bool         `json:"has_missing_deps"`     // 是否存在环境缺失
	MissingDependencies []string     `json:"missing_dependencies"` // 全部缺失依赖聚合警示清单
	Workers             []WorkerInfo `json:"workers"`              // 详细节点列表
}
