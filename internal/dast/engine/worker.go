package engine

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"devsecops/internal/config"
	"devsecops/internal/dast/service"
	dastpkg "devsecops/internal/dast"
	"devsecops/pkg/logger"
)

var (
	cancelledTasks   = make(map[string]bool)
	cancelledTasksMu sync.RWMutex
	resultFileMu     sync.Mutex
)

type PocDownloader interface {
	DownloadMatchedPocs(ctx context.Context, scanTags []string) (string, error)
}

func isTaskCancelled(taskID string) bool {
	cancelledTasksMu.RLock()
	defer cancelledTasksMu.RUnlock()
	return cancelledTasks[taskID]
}

func cancelTask(taskID string) {
	cancelledTasksMu.Lock()
	defer cancelledTasksMu.Unlock()
	cancelledTasks[taskID] = true
}

func startControlListener(ctx context.Context, rdb *service.QueueClient, keys service.QueueKeys) {
	pubsub := rdb.Subscribe(ctx, keys.ControlChannel())
	go func() {
		defer pubsub.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case message, ok := <-pubsub.Channel():
				if !ok {
					return
				}
				taskID := strings.TrimSpace(message.Payload)
				if taskID == "" {
					continue
				}
				cancelTask(taskID)
				logger.DAST("Control", "task %s cancellation received", taskID)
				_ = rdb.HSet(ctx, keys.StatusKey(taskID), "status", "stopped")
			}
		}
	}()
}

func saveResult(resultDir, taskID, entryType string, data interface{}) {
	resultFileMu.Lock()
	defer resultFileMu.Unlock()

	if resultDir == "" {
		resultDir = filepath.Join(".", "result", "dast")
	}
	_ = os.MkdirAll(resultDir, 0755)

	entry := struct {
		TaskID    string      `json:"taskId"`
		Type      string      `json:"type"`
		Timestamp string      `json:"timestamp"`
		Data      interface{} `json:"data"`
	}{
		TaskID:    taskID,
		Type:      entryType,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      data,
	}

	payload, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		logger.DAST("ResultSave", "marshal failed: %v", err)
		return
	}

	file, err := os.OpenFile(filepath.Join(resultDir, "result.json"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.DAST("ResultSave", "open file failed: %v", err)
		return
	}
	defer file.Close()

	_, _ = file.Write(append(payload, []byte("\n\n")...))
}

func RunPortWorker(ctx context.Context, cfg *config.Config, rdb *service.QueueClient, keys service.QueueKeys) {
	logger.DAST("PortWorker", "started, waiting for jobs on %s ...", keys.PortJobs())

	for {
		select {
		case <-ctx.Done():
			logger.DAST("PortWorker", "shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.PortJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.DAST("PortWorker", "blpop error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		var job dastpkg.PortJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.DAST("PortWorker", "invalid job: %v", err)
			continue
		}
		if isTaskCancelled(job.TaskId) {
			continue
		}

		start := time.Now()
		openPorts, err := ScanIP(ctx, job.IP, job.Ports, cfg.Dast)
		duration := time.Since(start)
		if err != nil {
			logger.DAST("PortWorker", "scan failed ip=%s err=%v cost=%s", job.IP, err, duration)
		}

		scanHost := job.IP
		if host, _, splitErr := net.SplitHostPort(job.IP); splitErr == nil {
			scanHost = host
		}

		for _, port := range openPorts {
			payload, _ := json.Marshal(dastpkg.FpJob{TaskId: job.TaskId, Host: scanHost, Port: port})
			_ = rdb.Push(ctx, keys.FpJobs(), string(payload))
		}

		if len(openPorts) == 0 {
			asset, _ := json.Marshal(dastpkg.DastAsset{
				Host:      scanHost,
				Port:      0,
				Proto:     "tcp",
				Service:   "unknown",
				Timestamp: time.Now().Format(time.RFC3339),
			})
			_ = rdb.Push(ctx, keys.AssetsKey(job.TaskId), string(asset))
		}

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "scanned_ips", 1)
		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "open_ports", int64(len(openPorts)))
		checkTaskCompletion(ctx, rdb, keys, job.TaskId)
		saveResult(cfg.Dast.ResultDir, job.TaskId, "port_scan", map[string]interface{}{
			"ip":    scanHost,
			"ports": openPorts,
		})
	}
}

func RunFpWorker(ctx context.Context, cfg *config.Config, rdb *service.QueueClient, keys service.QueueKeys) {
	logger.DAST("FpWorker", "started, waiting for jobs on %s ...", keys.FpJobs())

	for {
		select {
		case <-ctx.Done():
			logger.DAST("FpWorker", "shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.FpJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.DAST("FpWorker", "blpop error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		var job dastpkg.FpJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.DAST("FpWorker", "invalid job: %v", err)
			continue
		}
		if isTaskCancelled(job.TaskId) {
			continue
		}

		start := time.Now()
		var result ProbeResult
		var probeErr error

		isWeb, isTLS := SniffAndRoute(ctx, job.Host, job.Port)
		if isWeb {
			result, probeErr = WebFingerprint(ctx, job.Host, job.Port, isTLS)
			if probeErr != nil || len(result.Tags) == 0 {
				result, _ = ActiveProbe(ctx, job.Host, job.Port)
				_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_active_probe", 1)
			}
		} else {
			result, probeErr = NmapBinaryProbe(ctx, job.Host, job.Port)
			if probeErr != nil || result.Service == "" {
				result, _ = ActiveProbe(ctx, job.Host, job.Port)
				_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_active_probe", 1)
			}
		}

		if len(result.Tags) == 0 {
			result.Tags = FallbackTags
			result.Source = "fallback"
			_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_fallback", 1)
		}

		payload, _ := json.Marshal(dastpkg.PocJob{
			TaskId: job.TaskId,
			Target: result.URL,
			Proto:  result.Proto,
			Tags:   result.Tags,
		})
		_ = rdb.Push(ctx, keys.PocJobs(), string(payload))

		asset, _ := json.Marshal(dastpkg.DastAsset{
			Host:        job.Host,
			Port:        job.Port,
			Proto:       result.Proto,
			Service:     result.Service,
			Product:     result.Product,
			Version:     result.Version,
			CPEs:        result.CPEs,
			RawResponse: result.RawResponse,
			Timestamp:   time.Now().Format(time.RFC3339),
		})
		_ = rdb.Push(ctx, keys.AssetsKey(job.TaskId), string(asset))

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_done", 1)
		checkTaskCompletion(ctx, rdb, keys, job.TaskId)
		logger.DAST("FpWorker", "done host=%s:%d source=%s cost=%s", job.Host, job.Port, result.Source, time.Since(start))

		if result.Source == "active_probe" || result.Source == "fallback" {
			saveResult(cfg.Dast.ResultDir, job.TaskId, "fingerprint", map[string]interface{}{
				"host":     job.Host,
				"port":     job.Port,
				"proto":    result.Proto,
				"source":   result.Source,
				"tags":     result.Tags,
				"response": result.RawResponse,
			})
		} else {
			saveResult(cfg.Dast.ResultDir, job.TaskId, "fingerprint", map[string]interface{}{
				"host":   job.Host,
				"port":   job.Port,
				"proto":  result.Proto,
				"source": result.Source,
				"tags":   result.Tags,
			})
		}
	}
}

func RunPocWorker(ctx context.Context, cfg *config.Config, rdb *service.QueueClient, keys service.QueueKeys, pocSvc PocDownloader) {
	logger.DAST("PocWorker", "started, waiting for jobs on %s ...", keys.PocJobs())

	for {
		select {
		case <-ctx.Done():
			logger.DAST("PocWorker", "shutting down")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.PocJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.DAST("PocWorker", "blpop error: %v", err)
			time.Sleep(time.Second)
			continue
		}

		var job dastpkg.PocJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.DAST("PocWorker", "invalid job: %v", err)
			continue
		}
		if isTaskCancelled(job.TaskId) {
			continue
		}

		start := time.Now()
		tempPocDir, err := pocSvc.DownloadMatchedPocs(ctx, job.Tags)
		if err != nil || tempPocDir == "" {
			_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "poc_done", 1)
			checkTaskCompletion(ctx, rdb, keys, job.TaskId)
			continue
		}

		findings, scanErr := ScanWithTags(ctx, job.Target, job.Tags, tempPocDir)
		_ = os.RemoveAll(tempPocDir)
		if scanErr != nil {
			logger.DAST("PocWorker", "scan failed target=%s err=%v cost=%s", job.Target, scanErr, time.Since(start))
			_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "poc_done", 1)
			checkTaskCompletion(ctx, rdb, keys, job.TaskId)
			continue
		}

		for _, finding := range findings {
			payload, _ := json.Marshal(finding)
			_ = rdb.Push(ctx, keys.ResultsKey(job.TaskId), string(payload))
			saveResult(cfg.Dast.ResultDir, job.TaskId, "poc_finding", finding)
		}

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "poc_done", 1)
		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "findings", int64(len(findings)))
		checkTaskCompletion(ctx, rdb, keys, job.TaskId)
		saveResult(cfg.Dast.ResultDir, job.TaskId, "poc_scan", map[string]interface{}{
			"target":   job.Target,
			"tags":     job.Tags,
			"findings": len(findings),
		})
	}
}

func StartAllDastWorkers(ctx context.Context, cfg *config.Config, rdb *service.QueueClient, keys service.QueueKeys, pocSvc PocDownloader) {
	logger.Configure(cfg.Dast.LogDir, cfg.Dast.ConsoleLog)
	startControlListener(ctx, rdb, keys)

	go RunPortWorker(ctx, cfg, rdb, keys)
	go RunFpWorker(ctx, cfg, rdb, keys)
	go RunPocWorker(ctx, cfg, rdb, keys, pocSvc)

	logger.DAST("Init", "background workers started")
}

func checkTaskCompletion(ctx context.Context, rdb *service.QueueClient, keys service.QueueKeys, taskID string) {
	statusMap, err := rdb.Rdb.HGetAll(ctx, keys.StatusKey(taskID)).Result()
	if err != nil || len(statusMap) == 0 {
		return
	}

	currentStatus := statusMap["status"]
	if currentStatus == "success" || currentStatus == "stopped" || currentStatus == "stopping" {
		return
	}

	totalIPs, _ := strconv.Atoi(statusMap["total_ips"])
	scannedIPs, _ := strconv.Atoi(statusMap["scanned_ips"])
	openPorts, _ := strconv.Atoi(statusMap["open_ports"])
	fpDone, _ := strconv.Atoi(statusMap["fp_done"])
	pocDone, _ := strconv.Atoi(statusMap["poc_done"])

	if scannedIPs >= totalIPs && (openPorts == 0 || (fpDone >= openPorts && pocDone >= fpDone)) {
		_ = rdb.Rdb.HSet(ctx, keys.StatusKey(taskID), "status", "success")
	}
}
