package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	HeartbeatInterval = 5 * time.Second
	HeartbeatTTL      = 15 * time.Second

	KeyWorkerRegistered = "devsecops:worker:registered"
	KeyWorkerPrefix     = "devsecops:worker:info:"
)

// HeartbeatReporter 负责在 Worker 端定期自检环境并向 Redis 上报心跳
type HeartbeatReporter struct {
	rdb         *redis.Client
	workerID    string
	workerType  string
	startedAt   time.Time
	activeTasks int64
	diagnoseFn  func() ([]DependencyStatus, []string)
	workDir     string
}

// NewHeartbeatReporter 实例化 Worker 心跳上报器
func NewHeartbeatReporter(
	rdb *redis.Client,
	workerType string,
	workDir string,
	diagnoseFn func() ([]DependencyStatus, []string),
) *HeartbeatReporter {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	workerID := fmt.Sprintf("%s-%s-%d", workerType, hostname, os.Getpid())

	return &HeartbeatReporter{
		rdb:        rdb,
		workerID:   workerID,
		workerType: workerType,
		startedAt:  time.Now(),
		diagnoseFn: diagnoseFn,
		workDir:    workDir,
	}
}

func (h *HeartbeatReporter) WorkerID() string {
	return h.workerID
}

func (h *HeartbeatReporter) IncrActiveTasks() {
	atomic.AddInt64(&h.activeTasks, 1)
}

func (h *HeartbeatReporter) DecrActiveTasks() {
	atomic.AddInt64(&h.activeTasks, -1)
}

// Start 启动心跳守护循环
func (h *HeartbeatReporter) Start(ctx context.Context) {
	// 启动时立即上报一次
	h.report(ctx)

	ticker := time.NewTicker(HeartbeatInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				h.markOffline()
				return
			case <-ticker.C:
				h.report(ctx)
			}
		}
	}()
}

func (h *HeartbeatReporter) report(ctx context.Context) {
	var deps []DependencyStatus
	var missing []string
	if h.diagnoseFn != nil {
		deps, missing = h.diagnoseFn()
	}

	hostname, _ := os.Hostname()
	ip := getLocalIP()
	active := int(atomic.LoadInt64(&h.activeTasks))
	status := StatusOnline
	if active > 0 {
		status = StatusBusy
	}

	info := WorkerInfo{
		ID:            h.workerID,
		Type:          h.workerType,
		Hostname:      hostname,
		IP:            ip,
		PID:           os.Getpid(),
		Status:        status,
		Ready:         len(missing) == 0,
		StartedAt:     h.startedAt,
		LastHeartbeat: time.Now(),
		ActiveTasks:   active,
		SystemInfo: SystemInfo{
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
			NumCPU:    runtime.NumCPU(),
			GoVersion: runtime.Version(),
			WorkDir:   h.workDir,
		},
		Dependencies:   deps,
		MissingSummary: missing,
	}

	data, err := json.Marshal(info)
	if err != nil {
		log.Printf("[Heartbeat] 序列化失败: %v", err)
		return
	}

	pipe := h.rdb.Pipeline()
	key := fmt.Sprintf("%s%s:%s", KeyWorkerPrefix, h.workerType, h.workerID)
	pipe.Set(ctx, key, string(data), HeartbeatTTL)
	pipe.SAdd(ctx, KeyWorkerRegistered, fmt.Sprintf("%s:%s", h.workerType, h.workerID))
	_, err = pipe.Exec(ctx)
	if err != nil && ctx.Err() == nil {
		log.Printf("[Heartbeat] 心跳上报 Redis 失败: %v", err)
	}
}

func (h *HeartbeatReporter) markOffline() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	key := fmt.Sprintf("%s%s:%s", KeyWorkerPrefix, h.workerType, h.workerID)
	_ = h.rdb.Del(ctx, key).Err()
	_ = h.rdb.SRem(ctx, KeyWorkerRegistered, fmt.Sprintf("%s:%s", h.workerType, h.workerID)).Err()
}

// GetWorkersOverview 供 Server 读取所有已注册 Worker 的存活与依赖健康状况
func GetWorkersOverview(ctx context.Context, rdb *redis.Client) (*WorkersOverview, error) {
	registeredIDs, err := rdb.SMembers(ctx, KeyWorkerRegistered).Result()
	if err != nil {
		return nil, fmt.Errorf("读取注册 Worker 列表失败: %w", err)
	}

	overview := &WorkersOverview{
		TotalWorkers:        len(registeredIDs),
		AllReady:            true,
		MissingDependencies: []string{},
		Workers:             make([]WorkerInfo, 0, len(registeredIDs)),
	}

	var toClean []string

	for _, regKey := range registeredIDs {
		key := fmt.Sprintf("%s%s", KeyWorkerPrefix, regKey)
		val, err := rdb.Get(ctx, key).Result()
		if err == redis.Nil || val == "" {
			// 该 Worker 超过 TTL 已经下线，记录待清理并展示为离线
			parts := strings.SplitN(regKey, ":", 2)
			wType := "unknown"
			wID := regKey
			if len(parts) == 2 {
				wType = parts[0]
				wID = parts[1]
			}
			toClean = append(toClean, regKey)
			overview.Workers = append(overview.Workers, WorkerInfo{
				ID:     wID,
				Type:   wType,
				Status: StatusOffline,
				Ready:  false,
			})
			continue
		} else if err != nil {
			continue
		}

		var info WorkerInfo
		if err := json.Unmarshal([]byte(val), &info); err != nil {
			continue
		}

		overview.OnlineWorkers++
		if info.Type == TypeSAST {
			overview.SastOnline++
		} else if info.Type == TypeDAST {
			overview.DastOnline++
		}

		if !info.Ready || len(info.MissingSummary) > 0 {
			overview.AllReady = false
			overview.HasMissingDeps = true
			for _, m := range info.MissingSummary {
				overview.MissingDependencies = append(overview.MissingDependencies, fmt.Sprintf("[%s] %s", info.ID, m))
			}
		}

		overview.Workers = append(overview.Workers, info)
	}

	// 异步清理已离线超过清理周期的注册项
	if len(toClean) > 0 {
		go func(keys []string) {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			for _, k := range keys {
				_ = rdb.SRem(cleanCtx, KeyWorkerRegistered, k).Err()
			}
		}(toClean)
	}

	// 排序：在线节点排在前面，同状态按 ID 排序
	sort.Slice(overview.Workers, func(i, j int) bool {
		if overview.Workers[i].Status != overview.Workers[j].Status {
			return overview.Workers[i].Status == StatusOnline || overview.Workers[i].Status == StatusBusy
		}
		return overview.Workers[i].ID < overview.Workers[j].ID
	})

	if overview.OnlineWorkers == 0 {
		overview.AllReady = false
	}

	return overview, nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
