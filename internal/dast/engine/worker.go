package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"devsecops/internal/config"
	"devsecops/internal/dast/logger"
	"devsecops/internal/dast/queue"
	"devsecops/internal/model"
)

var (
	cancelledTasks   = make(map[string]bool)
	cancelledTasksMu sync.RWMutex
	resultFileMu     sync.Mutex
)

func isTaskCancelled(taskId string) bool {
	cancelledTasksMu.RLock()
	defer cancelledTasksMu.RUnlock()
	return cancelledTasks[taskId]
}

func cancelTask(taskId string) {
	cancelledTasksMu.Lock()
	defer cancelledTasksMu.Unlock()
	cancelledTasks[taskId] = true
}

func startControlListener(ctx context.Context, rdb *queue.QueueClient, keys queue.QueueKeys) {
	pubsub := rdb.Subscribe(ctx, keys.Prefix+":control")
	go func() {
		defer pubsub.Close()
		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				taskId := strings.TrimSpace(msg.Payload)
				if taskId != "" {
					cancelTask(taskId)
					logger.Printf("[control] DAST Task %s cancellation received. Skipping future jobs.\n", taskId)
				}
			}
		}
	}()
}

func saveResult(taskId, entryType string, data interface{}) {
	resultFileMu.Lock()
	defer resultFileMu.Unlock()

	_ = os.MkdirAll("result", 0755)

	entry := struct {
		TaskId    string      `json:"taskId"`
		Type      string      `json:"type"`
		Timestamp string      `json:"timestamp"`
		Data      interface{} `json:"data"`
	}{
		TaskId:    taskId,
		Type:      entryType,
		Timestamp: time.Now().Format(time.RFC3339),
		Data:      data,
	}

	b, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		logger.Printf("[result-save] marshal failed: %v\n", err)
		return
	}

	f, err := os.OpenFile(filepath.Join("result", "result.json"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Printf("[result-save] open file failed: %v\n", err)
		return
	}
	defer f.Close()

	_, _ = f.Write(append(b, []byte("\n\n")...))
}

func RunPortWorker(ctx context.Context, cfg *config.Config, rdb *queue.QueueClient, keys queue.QueueKeys) {
	logger.Printf("[port-worker] started, waiting for jobs on %s ...\n", keys.PortJobs())

	for {
		select {
		case <-ctx.Done():
			logger.Printf("[port-worker] shutting down\n")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.PortJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("[port-worker] blpop error: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var job model.PortJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.Printf("[port-worker] invalid job: %v\n", err)
			continue
		}

		if isTaskCancelled(job.TaskId) {
			logger.Printf("[port-worker] skipped job for cancelled taskId=%s\n", job.TaskId)
			continue
		}

		logger.Printf("[port-worker] scanning taskId=%s ip=%s\n", job.TaskId, job.IP)

		startTime := time.Now()
		openPorts, err := ScanIP(ctx, job.IP, job.Ports, cfg.Dast)
		duration := time.Since(startTime)
		if err != nil {
			logger.Printf("[port-worker] scan failed ip=%s err=%v, cost=%s\n", job.IP, err, duration)
		}

		scanHost := job.IP
		if h, _, err := net.SplitHostPort(job.IP); err == nil {
			scanHost = h
		}

		for _, port := range openPorts {
			fpJob := model.FpJob{
				TaskId: job.TaskId,
				Host:   scanHost,
				Port:   port,
			}
			data, _ := json.Marshal(fpJob)
			_ = rdb.Push(ctx, keys.FpJobs(), string(data))
		}

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "scanned_ips", 1)
		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "open_ports", int64(len(openPorts)))
		logger.Printf("[port-worker] done ip=%s open=%d ports, pushed to %s, cost=%s\n",
			job.IP, len(openPorts), keys.FpJobs(), duration)

		saveResult(job.TaskId, "port_scan", struct {
			IP    string `json:"ip"`
			Ports []int  `json:"ports"`
		}{
			IP:    scanHost,
			Ports: openPorts,
		})
	}
}

func RunFpWorker(ctx context.Context, cfg *config.Config, rdb *queue.QueueClient, keys queue.QueueKeys) {
	logger.Printf("[fp-worker] started, waiting for jobs on %s ...\n", keys.FpJobs())

	for {
		select {
		case <-ctx.Done():
			logger.Printf("[fp-worker] shutting down\n")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.FpJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("[fp-worker] blpop error: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var job model.FpJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.Printf("[fp-worker] invalid job: %v\n", err)
			continue
		}

		if isTaskCancelled(job.TaskId) {
			logger.Printf("[fp-worker] skipped job for cancelled taskId=%s\n", job.TaskId)
			continue
		}

		logger.Printf("[fp-worker] probing taskId=%s host=%s port=%d\n", job.TaskId, job.Host, job.Port)

		startTime := time.Now()
		result, err := NmapProbe(ctx, job.Host, job.Port)
		duration := time.Since(startTime)
		if err != nil {
			isTimeout := strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), "deadline exceeded")
			if isTimeout {
				logger.Printf("[fp-worker] nmap-probe timed out on %s:%d. Skipping retry. cost=%s\n", job.Host, job.Port, duration)
				result = ProbeResult{
					URL:         fmt.Sprintf("%s:%d", job.Host, job.Port),
					Proto:       "tcp",
					Tags:        FallbackTags,
					RawResponse: fmt.Sprintf("nmap probe timed out: %v", err),
				}
			} else {
				if job.Retry < 3 {
					job.Retry++
					job.FailReason = fmt.Sprintf("retry %d/3: %v", job.Retry, err)
					data, _ := json.Marshal(job)
					_ = rdb.Push(ctx, keys.FpJobs(), string(data))
					logger.Printf("[fp-worker] nmap-probe error on %s:%d, retrying (%d/3): %v, cost=%s\n", job.Host, job.Port, job.Retry, err, duration)
					continue
				}
				logger.Printf("[fp-worker] nmap-probe error on %s:%d, max retries reached: %v. falling back. cost=%s\n", job.Host, job.Port, err, duration)
				result = ProbeResult{
					URL:         fmt.Sprintf("%s:%d", job.Host, job.Port),
					Proto:       "tcp",
					Tags:        FallbackTags,
					RawResponse: fmt.Sprintf("nmap probe failed: %v", err),
				}
			}
		} else {
			if len(result.Tags) == 0 {
				result.Tags = FallbackTags
				logger.Printf("[fp-worker] no fingerprint matched for %s:%d (proto=%s), using fallback tags\n",
					job.Host, job.Port, result.Proto)
				_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_fallback", 1)
			}
		}

		pocJob := model.PocJob{
			TaskId: job.TaskId,
			Target: result.URL,
			Proto:  result.Proto,
			Tags:   result.Tags,
			Retry:  0,
		}

		data, _ := json.Marshal(pocJob)
		_ = rdb.Push(ctx, keys.PocJobs(), string(data))

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "fp_done", 1)
		logger.Printf("[fp-worker] done host=%s:%d → target=%s tags=%v, cost=%s\n",
			job.Host, job.Port, result.URL, result.Tags, duration)

		isFallback := len(result.Tags) == 3 && result.Tags[0] == "exposure" && result.Tags[1] == "misconfig" && result.Tags[2] == "config"
		if isFallback {
			saveResult(job.TaskId, "fingerprint", struct {
				Host     string   `json:"host"`
				Port     int      `json:"port"`
				Proto    string   `json:"proto"`
				Tags     []string `json:"tags"`
				Response string   `json:"response"`
			}{
				Host:     job.Host,
				Port:     job.Port,
				Proto:    result.Proto,
				Tags:     result.Tags,
				Response: result.RawResponse,
			})
		} else {
			saveResult(job.TaskId, "fingerprint", struct {
				Host  string   `json:"host"`
				Port  int      `json:"port"`
				Proto string   `json:"proto"`
				Tags  []string `json:"tags"`
			}{
				Host:  job.Host,
				Port:  job.Port,
				Proto: result.Proto,
				Tags:  result.Tags,
			})
		}
	}
}

func RunPocWorker(ctx context.Context, cfg *config.Config, rdb *queue.QueueClient, keys queue.QueueKeys) {
	logger.Printf("[poc-worker] started, waiting for jobs on %s ...\n", keys.PocJobs())

	for {
		select {
		case <-ctx.Done():
			logger.Printf("[poc-worker] shutting down\n")
			return
		default:
		}

		raw, err := rdb.BLPop(ctx, keys.PocJobs())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Printf("[poc-worker] blpop error: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		var job model.PocJob
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			logger.Printf("[poc-worker] invalid job: %v\n", err)
			continue
		}

		if isTaskCancelled(job.TaskId) {
			logger.Printf("[poc-worker] skipped job for cancelled taskId=%s\n", job.TaskId)
			continue
		}

		logger.Printf("[poc-worker] scanning taskId=%s target=%s tags=%v\n",
			job.TaskId, job.Target, job.Tags)

		startTime := time.Now()
		findings, err := ScanWithTags(ctx, job.Target, job.Tags, cfg.Dast.PocDir)
		duration := time.Since(startTime)

		if err != nil {
			logger.Printf("[poc-worker] scan failed target=%s: %v, cost=%s\n",
				job.Target, err, duration)
			_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "poc_done", 1)
			continue
		}

		for _, f := range findings {
			b, _ := json.Marshal(f)
			_ = rdb.Push(ctx, keys.ResultsKey(job.TaskId), string(b))
			logger.Printf("[poc-worker] FINDING taskId=%s template=%s severity=%s matched=%s\n",
				job.TaskId, f.TemplateID, f.Severity, f.Matched)
			saveResult(job.TaskId, "poc_finding", f)
		}

		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "poc_done", 1)
		_ = rdb.HIncrBy(ctx, keys.StatusKey(job.TaskId), "findings", int64(len(findings)))
		logger.Printf("[poc-worker] done target=%s findings=%d cost=%s\n",
			job.Target, len(findings), duration)

		saveResult(job.TaskId, "poc_scan", struct {
			Target   string   `json:"target"`
			Tags     []string `json:"tags"`
			Findings int      `json:"findings"`
		}{
			Target:   job.Target,
			Tags:     job.Tags,
			Findings: len(findings),
		})
	}
}

func StartAllDastWorkers(ctx context.Context, cfg *config.Config) {
	keys := queue.NewQueueKeys(cfg.Dast.QueuePrefix)
	rdb := queue.NewQueueClient(cfg.Redis, cfg.DastDialTimeout(), cfg.DastReadTimeout())

	startControlListener(ctx, rdb, keys)

	go RunPortWorker(ctx, cfg, rdb, keys)
	go RunFpWorker(ctx, cfg, rdb, keys)
	go RunPocWorker(ctx, cfg, rdb, keys)

	logger.Printf("[DAST] All background workers (PortScan, Fingerprint, NucleiPOC) started.\n")
}
