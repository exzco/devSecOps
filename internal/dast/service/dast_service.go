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
	"devsecops/internal/dast/queue"
	"devsecops/internal/model"
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
	Status     string `json:"status"`
	TotalIPs   int    `json:"total_ips"`
	ScannedIPs int    `json:"scanned_ips"`
	OpenPorts  int    `json:"open_ports"`
	FpDone     int    `json:"fp_done"`
	PocDone    int    `json:"poc_done"`
	Findings   int    `json:"findings"`
	StartedAt  string `json:"started_at"`
}

func (s *DastService) CreateTask(ctx context.Context, taskID, ipsStr, portsStr string) (string, int, error) {
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

	// 1. Clear previous task residue if exists
	s.rdb.Del(ctx, s.keys.StatusKey(taskId), s.keys.ResultsKey(taskId))

	// 2. Initialize task status in Redis
	s.rdb.HSet(ctx, s.keys.StatusKey(taskId),
		"status", "running",
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
			Status:     statusMap["status"],
			TotalIPs:   totalIPs,
			ScannedIPs: scannedIPs,
			OpenPorts:  openPorts,
			FpDone:     fpDone,
			PocDone:    pocDone,
			Findings:   findings,
			StartedAt:  statusMap["started_at"],
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
	s.rdb.Del(ctx, s.keys.StatusKey(taskId), s.keys.ResultsKey(taskId))
	s.rdb.SRem(ctx, s.keys.Prefix+":all_tasks", taskId)
	return nil
}
