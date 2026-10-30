package dast

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/config"
	"devsecops/internal/messaging"
	"devsecops/internal/model"
)

type DastService struct {
	rdb          *redis.Client
	keyPrefix    string
	defaultPorts string
}

func (s *DastService) Close() error {
	return nil
}

func NewDastService(rdb *redis.Client, cfg config.DastConfig) *DastService {
	return &DastService{
		rdb:          rdb,
		keyPrefix:    cfg.QueuePrefix,
		defaultPorts: cfg.DefaultPorts,
	}
}

func (s *DastService) CreateTask(ctx context.Context, taskID, taskName, ipsStr, portsStr string) (string, int, error) {
	taskId := strings.TrimSpace(taskID)
	if taskId == "" {
		taskId = fmt.Sprintf("dast-%d", time.Now().UnixNano()/1e6)
	}

	var ips []string
	cleaner := strings.NewReplacer(",", " ", ";", " ", "\n", " ", "\t", " ")
	for _, raw := range strings.Split(cleaner.Replace(ipsStr), " ") {
		raw = strings.TrimSpace(raw)
		if raw != "" {
			norm := model.ParseTarget(raw)
			if norm.IsValid {
				if norm.Kind == "HOST_PORT" || hasExplicitURLPort(raw, norm) {
					ips = append(ips, raw)
				} else {
					ips = append(ips, norm.Host)
				}
			} else {
				ips = append(ips, raw)
			}
		}
	}

	if len(ips) == 0 {
		return "", 0, fmt.Errorf("no valid IPs provided")
	}

	ports := portsStr
	if ports == "" {
		ports = s.defaultPorts
	}
	if ports == "" {
		ports = "top1000"
	}

	name := strings.TrimSpace(taskName)
	if name == "" {
		name = taskId
	}

	s.deleteTaskState(ctx, taskId)

	now := time.Now().Format("2006-01-02 15:04:05")
	statusData := map[string]interface{}{
		"task_id":         taskId,
		"task_name":       name,
		"status":          "running",
		"total_targets":   len(ips),
		"scanned_targets": 0,
		"open_ports":      0,
		"findings":        0,
		"errors":          0,
		"started_at":      now,
		"ips":             ipsStr,
		"ports":           ports,
	}

	if err := s.rdb.HSet(ctx, model.StatusKey(s.keyPrefix, taskId), statusData).Err(); err != nil {
		return "", 0, fmt.Errorf("failed to init task status: %w", err)
	}

	defaultPolicy := model.DefaultPolicy()
	defaultPolicy.PortProfile = ports

	rawTask := model.WorkItem{
		ScanRunID:  taskId,
		RawTargets: ips,
		PortRange:  ports,
		Profile:    "balanced",
		Policy:     *defaultPolicy,
	}

	streamClient := messaging.NewStreamClient(s.rdb)
	if _, err := streamClient.Publish(ctx, messaging.DefaultRawStream, rawTask); err != nil {
		s.deleteTaskState(ctx, taskId)
		return "", 0, fmt.Errorf("failed to publish task to redis stream: %w", err)
	}
	if err := s.rdb.SAdd(ctx, model.AllTasksKey(s.keyPrefix), taskId).Err(); err != nil {
		_ = s.deleteTaskState(ctx, taskId)
		return "", 0, fmt.Errorf("failed to register task: %w", err)
	}

	return taskId, len(ips), nil
}

func hasExplicitURLPort(raw string, target *model.Target) bool {
	if target == nil || target.Kind != "URL" || target.Port == 0 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Port() != ""
}

func (s *DastService) ListTasks(ctx context.Context) ([]model.DastTaskSummary, error) {
	taskIDs, err := s.rdb.SMembers(ctx, model.AllTasksKey(s.keyPrefix)).Result()
	if err != nil {
		return nil, err
	}

	var tasks []model.DastTaskSummary
	for _, id := range taskIDs {
		data, err := s.rdb.HGetAll(ctx, model.StatusKey(s.keyPrefix, id)).Result()
		if err != nil || len(data) == 0 {
			continue
		}

		totalTargets, _ := strconv.Atoi(data["total_targets"])
		scannedTargets, _ := strconv.Atoi(data["scanned_targets"])
		openPorts, _ := strconv.Atoi(data["open_ports"])
		findings, _ := strconv.Atoi(data["findings"])
		errorsCount, _ := strconv.Atoi(data["errors"])

		tasks = append(tasks, model.DastTaskSummary{
			TaskID:         id,
			TaskName:       data["task_name"],
			Status:         data["status"],
			TotalTargets:   totalTargets,
			ScannedTargets: scannedTargets,
			OpenPorts:      openPorts,
			Findings:       findings,
			Errors:         errorsCount,
			StartedAt:      data["started_at"],
			FinishedAt:     data["finished_at"],
			IPs:            data["ips"],
			Ports:          data["ports"],
		})
	}

	sort.Slice(tasks, func(i, j int) bool {
		return tasks[i].StartedAt > tasks[j].StartedAt
	})

	return tasks, nil
}

func (s *DastService) GetTaskStatus(ctx context.Context, taskID string) (map[string]string, error) {
	data, err := s.rdb.HGetAll(ctx, model.StatusKey(s.keyPrefix, taskID)).Result()
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("task not found: %s", taskID)
	}
	return data, nil
}

func (s *DastService) GetTaskResults(ctx context.Context, taskID string) ([]model.Finding, error) {
	raws, err := s.rdb.LRange(ctx, model.FindingsKey(s.keyPrefix, taskID), 0, -1).Result()
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(raws))
	findings := make([]model.Finding, 0, len(raws))
	for _, raw := range raws {
		var finding model.Finding
		if err := json.Unmarshal([]byte(raw), &finding); err != nil {
			continue
		}
		key := finding.StableKey
		if key == "" {
			key = finding.ID
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, finding)
	}
	return findings, nil
}

func (s *DastService) GetTaskAssets(ctx context.Context, taskID string) ([]model.Service, error) {
	raws, err := s.rdb.LRange(ctx, model.AssetsKey(s.keyPrefix, taskID), 0, -1).Result()
	if err != nil {
		return nil, err
	}
	assets := make([]model.Service, 0, len(raws))
	for _, raw := range raws {
		var a model.Service
		if err := json.Unmarshal([]byte(raw), &a); err == nil {
			assets = append(assets, a)
		}
	}
	return assets, nil
}

func (s *DastService) DeleteTask(ctx context.Context, taskID string) error {
	status, err := s.GetTaskStatus(ctx, taskID)
	if err != nil {
		return err
	}
	if status["status"] == "running" {
		return fmt.Errorf("cannot delete a running dast task")
	}

	if err := s.deleteTaskState(ctx, taskID); err != nil {
		return err
	}
	return s.rdb.SRem(ctx, model.AllTasksKey(s.keyPrefix), taskID).Err()
}

func (s *DastService) deleteTaskState(ctx context.Context, taskID string) error {
	return s.rdb.Del(
		ctx,
		model.StatusKey(s.keyPrefix, taskID),
		model.ResultsKey(s.keyPrefix, taskID),
		model.FindingsKey(s.keyPrefix, taskID),
		model.AssetsKey(s.keyPrefix, taskID),
		model.TargetsKey(s.keyPrefix, taskID),
	).Err()
}

func (s *DastService) CreateConfig(ctx context.Context, taskName, ipsStr, portsStr string) (*model.DastConfig, error) {
	configID := fmt.Sprintf("cfg-%d", time.Now().UnixNano()/1e6)
	cfg := &model.DastConfig{
		ConfigID:  configID,
		TaskName:  taskName,
		IPs:       ipsStr,
		Ports:     portsStr,
		CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	if err := s.rdb.Set(ctx, model.ConfigKey(s.keyPrefix, configID), data, 0).Err(); err != nil {
		return nil, err
	}
	if err := s.rdb.SAdd(ctx, model.AllConfigsKey(s.keyPrefix), configID).Err(); err != nil {
		_ = s.rdb.Del(ctx, model.ConfigKey(s.keyPrefix, configID)).Err()
		return nil, err
	}

	return cfg, nil
}

func (s *DastService) ListConfigs(ctx context.Context) ([]model.DastConfig, error) {
	ids, err := s.rdb.SMembers(ctx, model.AllConfigsKey(s.keyPrefix)).Result()
	if err != nil {
		return nil, err
	}

	var configs []model.DastConfig
	for _, id := range ids {
		val, err := s.rdb.Get(ctx, model.ConfigKey(s.keyPrefix, id)).Result()
		if err != nil || val == "" {
			continue
		}
		var cfg model.DastConfig
		if err := json.Unmarshal([]byte(val), &cfg); err == nil {
			configs = append(configs, cfg)
		}
	}

	sort.Slice(configs, func(i, j int) bool {
		return configs[i].CreatedAt > configs[j].CreatedAt
	})
	return configs, nil
}

func (s *DastService) UpdateConfig(ctx context.Context, configID, taskName, ipsStr, portsStr string) (*model.DastConfig, error) {
	val, err := s.rdb.Get(ctx, model.ConfigKey(s.keyPrefix, configID)).Result()
	if err != nil || val == "" {
		return nil, fmt.Errorf("config not found: %s", configID)
	}

	var cfg model.DastConfig
	if err := json.Unmarshal([]byte(val), &cfg); err != nil {
		return nil, fmt.Errorf("decode config %s: %w", configID, err)
	}

	cfg.TaskName = taskName
	cfg.IPs = ipsStr
	cfg.Ports = portsStr

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}

	if err := s.rdb.Set(ctx, model.ConfigKey(s.keyPrefix, configID), data, 0).Err(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (s *DastService) DeleteConfig(ctx context.Context, configID string) error {
	if err := s.rdb.Del(ctx, model.ConfigKey(s.keyPrefix, configID)).Err(); err != nil {
		return err
	}
	return s.rdb.SRem(ctx, model.AllConfigsKey(s.keyPrefix), configID).Err()
}
