package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	"devsecops/internal/dast/model"
	"devsecops/internal/dast/queue"
)

type DastService struct {
	rdb  *redis.Client
	keys queue.QueueKeys
}

func NewDastService(redisCfg *config.RedisConfig, prefix string) *DastService {
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisCfg.Addr,
		Password: redisCfg.Password,
		DB:       redisCfg.DB,
	})
	return &DastService{
		rdb:  rdb,
		keys: queue.NewQueueKeys(prefix),
	}
}

type DastTaskSummary struct {
	TaskID     string `json:"task_id"`
	TaskName   string `json:"task_name"`
	Status     string `json:"status"`
	TotalIPs   int    `json:"total_ips"`
	ScannedIPs int    `json:"scanned_ips"`
	OpenPorts  int    `json:"open_ports"`
	FpDone     int    `json:"fp_done"`
	PocDone    int    `json:"poc_done"`
	Findings   int    `json:"findings"`
	StartedAt  string `json:"started_at"`
	IPs        string `json:"ips"`   // 原始目标 IP，用于重新触发时复用
	Ports      string `json:"ports"` // 原始端口配置，用于重新触发时复用
}

// DastConfig 表示持久化的扫描任务模板，与扫描执行记录相互独立
type DastConfig struct {
	ConfigID  string `json:"config_id"`
	TaskName  string `json:"task_name"`
	IPs       string `json:"ips"`
	Ports     string `json:"ports"`
	CreatedAt string `json:"created_at"`
}

func (s *DastService) CreateTask(ctx context.Context, taskID, taskName, ipsStr, portsStr string) (string, int, error) {
	taskId := strings.TrimSpace(taskID)
	if taskId == "" {
		taskId = fmt.Sprintf("dast-%d", time.Now().UnixNano()/1e6)
	}

	var ips []string
	for _, ip := range strings.Split(ipsStr, " ") {
		if ip = strings.TrimSpace(ip); ip != "" {
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		return "", 0, fmt.Errorf("no valid IPs provided")
	}

	ports := portsStr
	if ports == "" {
		ports = "top1000"
	}

	name := strings.TrimSpace(taskName)
	if name == "" {
		name = taskId
	}

	// 1. Clear previous task residue if exists
	s.rdb.Del(ctx, s.keys.StatusKey(taskId), s.keys.ResultsKey(taskId))

	// 2. Initialize task status in Redis（同时存储原始配置，用于重新触发时复用）
	s.rdb.HSet(ctx, s.keys.StatusKey(taskId),
		"status", "running",
		"task_name", name,
		"ips", ipsStr,
		"ports", portsStr,
		"total_ips", len(ips),
		"started_at", time.Now().Format(time.RFC3339),
		"scanned_ips", 0,
		"open_ports", 0,
		"fp_done", 0,
		"poc_done", 0,
		"findings", 0,
	)

	// 3. Track task ID in global list
	s.rdb.SAdd(ctx, s.keys.Prefix+":all_tasks", taskId)

	// 4. Push PortJobs to Redis queue
	for _, rawIP := range ips {
		jobIP := rawIP
		jobPorts := ports

		if host, portStr, err := net.SplitHostPort(rawIP); err == nil {
			jobIP = host
			jobPorts = portStr
		}

		job := model.PortJob{
			TaskId: taskId,
			IP:     jobIP,
			Ports:  jobPorts,
		}
		data, _ := json.Marshal(job)
		s.rdb.RPush(ctx, s.keys.PortJobs(), string(data))
	}

	return taskId, len(ips), nil
}

func (s *DastService) ListTasks(ctx context.Context) ([]DastTaskSummary, error) {
	taskIds, err := s.rdb.SMembers(ctx, s.keys.Prefix+":all_tasks").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tasks: %w", err)
	}

	tasks := make([]DastTaskSummary, 0, len(taskIds))
	for _, id := range taskIds {
		statusMap, err := s.rdb.HGetAll(ctx, s.keys.StatusKey(id)).Result()
		if err != nil || len(statusMap) == 0 {
			continue
		}

		totalIPs, _ := strconv.Atoi(statusMap["total_ips"])
		scannedIPs, _ := strconv.Atoi(statusMap["scanned_ips"])
		openPorts, _ := strconv.Atoi(statusMap["open_ports"])
		fpDone, _ := strconv.Atoi(statusMap["fp_done"])
		pocDone, _ := strconv.Atoi(statusMap["poc_done"])
		findings, _ := strconv.Atoi(statusMap["findings"])

		tasks = append(tasks, DastTaskSummary{
			TaskID:     id,
			TaskName:   statusMap["task_name"],
			Status:     statusMap["status"],
			TotalIPs:   totalIPs,
			ScannedIPs: scannedIPs,
			OpenPorts:  openPorts,
			FpDone:     fpDone,
			PocDone:    pocDone,
			Findings:   findings,
			StartedAt:  statusMap["started_at"],
			IPs:        statusMap["ips"],
			Ports:      statusMap["ports"],
		})
	}

	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].StartedAt > tasks[j].StartedAt
	})

	return tasks, nil
}

func (s *DastService) GetTaskStatus(ctx context.Context, taskId string) (map[string]string, error) {
	statusMap, err := s.rdb.HGetAll(ctx, s.keys.StatusKey(taskId)).Result()
	if err != nil {
		return nil, err
	}
	if len(statusMap) == 0 {
		return nil, fmt.Errorf("task not found")
	}
	return statusMap, nil
}

func (s *DastService) GetTaskResults(ctx context.Context, taskId string) ([]interface{}, error) {
	results, err := s.rdb.LRange(ctx, s.keys.ResultsKey(taskId), 0, -1).Result()
	if err != nil {
		return nil, err
	}

	var findings []interface{}
	for _, raw := range results {
		var f interface{}
		if err := json.Unmarshal([]byte(raw), &f); err == nil {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func (s *DastService) DeleteTask(ctx context.Context, taskId string) error {
	// 如果任务正在运行或停止中，发送取消信号中止扫描 worker
	statusMap, err := s.rdb.HGetAll(ctx, s.keys.StatusKey(taskId)).Result()
	if err == nil && (statusMap["status"] == "running" || statusMap["status"] == "stopping") {
		controlKey := s.keys.Prefix + ":control"
		s.rdb.Publish(ctx, controlKey, taskId)
	}

	// 仅删除执行记录（status/results/assets）和任务运行列表
	// 不删除配置模板（ConfigKey 和 all_configs），保护“扫描任务配置”页的持久配置
	s.rdb.Del(ctx, s.keys.StatusKey(taskId), s.keys.ResultsKey(taskId), s.keys.AssetsKey(taskId))
	s.rdb.SRem(ctx, s.keys.Prefix+":all_tasks", taskId)
	return nil
}

func (s *DastService) StopTask(ctx context.Context, taskId string) error {
	// 1. Mark task status as "stopping" (正在停止) immediately so the UI reflects it
	if err := s.rdb.HSet(ctx, s.keys.StatusKey(taskId), "status", "stopping").Err(); err != nil {
		return fmt.Errorf("failed to update status to stopping: %w", err)
	}

	// 2. Publish cancel message to Redis control channel to abort ongoing queue jobs
	controlKey := s.keys.Prefix + ":control"
	if err := s.rdb.Publish(ctx, controlKey, taskId).Err(); err != nil {
		return fmt.Errorf("failed to publish stop signal: %w", err)
	}

	return nil
}

func (s *DastService) GetTaskAssets(ctx context.Context, taskId string) ([]model.DastAsset, error) {
	results, err := s.rdb.LRange(ctx, s.keys.AssetsKey(taskId), 0, -1).Result()
	if err != nil {
		return nil, err
	}

	var assets []model.DastAsset
	for _, raw := range results {
		var asset model.DastAsset
		if err := json.Unmarshal([]byte(raw), &asset); err == nil {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

// ==================== 扫描配置模板 CRUD ====================

// CreateConfig 创建持久化扫描配置模板，与扫描执行记录完全独立
func (s *DastService) CreateConfig(ctx context.Context, configID, taskName, ips, ports string) error {
	if configID == "" {
		configID = fmt.Sprintf("cfg-%d", time.Now().UnixNano()/1e6)
	}
	s.rdb.HSet(ctx, s.keys.ConfigKey(configID),
		"config_id", configID,
		"task_name", taskName,
		"ips", ips,
		"ports", ports,
		"created_at", time.Now().Format(time.RFC3339),
	)
	s.rdb.SAdd(ctx, s.keys.AllConfigsKey(), configID)
	return nil
}

// ListConfigs 返回所有持久化配置模板
func (s *DastService) ListConfigs(ctx context.Context) ([]DastConfig, error) {
	configIDs, err := s.rdb.SMembers(ctx, s.keys.AllConfigsKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch configs: %w", err)
	}

	configs := make([]DastConfig, 0, len(configIDs))
	for _, id := range configIDs {
		m, err := s.rdb.HGetAll(ctx, s.keys.ConfigKey(id)).Result()
		if err != nil || len(m) == 0 {
			continue
		}
		configs = append(configs, DastConfig{
			ConfigID:  m["config_id"],
			TaskName:  m["task_name"],
			IPs:       m["ips"],
			Ports:     m["ports"],
			CreatedAt: m["created_at"],
		})
	}

	// 按创建时间降序排列
	sort.Slice(configs, func(i, j int) bool {
		return configs[i].CreatedAt > configs[j].CreatedAt
	})
	return configs, nil
}

// DeleteConfig 删除配置模板（仅删配置，不影响扫描记录）
func (s *DastService) DeleteConfig(ctx context.Context, configID string) error {
	s.rdb.Del(ctx, s.keys.ConfigKey(configID))
	s.rdb.SRem(ctx, s.keys.AllConfigsKey(), configID)
	return nil
}

// UpdateConfig 更新持久化扫描配置模板
func (s *DastService) UpdateConfig(ctx context.Context, configID, taskName, ips, ports string) error {
	exists, err := s.rdb.Exists(ctx, s.keys.ConfigKey(configID)).Result()
	if err != nil || exists == 0 {
		return fmt.Errorf("config %s not found", configID)
	}

	s.rdb.HSet(ctx, s.keys.ConfigKey(configID),
		"task_name", taskName,
		"ips", ips,
		"ports", ports,
	)
	return nil
}
