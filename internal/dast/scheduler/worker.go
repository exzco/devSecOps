package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"devsecops/internal/dast/engine"
	"devsecops/internal/messaging"
	"devsecops/internal/model"
)

const finishTargetScript = `
if redis.call("SADD", KEYS[2], ARGV[1]) == 0 then
  return {redis.call("HGET", KEYS[1], "scanned_targets") or "0", redis.call("HGET", KEYS[1], "status") or ""}
end

local status = redis.call("HGET", KEYS[1], "status") or "running"
if status == "cancelled" then
  return {redis.call("HGET", KEYS[1], "scanned_targets") or "0", status}
end

local total = tonumber(redis.call("HGET", KEYS[1], "total_targets") or "0")
local scanned = redis.call("HINCRBY", KEYS[1], "scanned_targets", 1)
local failed = redis.call("HINCRBY", KEYS[1], "errors", ARGV[2])
redis.call("HINCRBY", KEYS[1], "open_ports", ARGV[3])
redis.call("HINCRBY", KEYS[1], "findings", ARGV[4])
redis.call("HINCRBY", KEYS[1], "services_found", ARGV[5])
redis.call("HINCRBY", KEYS[1], "endpoints_found", ARGV[6])

if total > 0 and scanned >= total then
  if failed >= total then
    status = "failed"
  else
    status = "completed"
  end
  redis.call("HSET", KEYS[1], "status", status)
  redis.call("HSET", KEYS[1], "finished_at", ARGV[7])
end
return {scanned, status}
`

func writeScanResult(
	ctx context.Context,
	rdb *redis.Client,
	prefix string,
	runID string,
	target string,
	result *engine.ScanResult,
	scanErr error,
) error {
	failed := 0
	openPorts := 0
	findingsCount := 0
	servicesCount := 0
	endpointsCount := 0

	if result != nil {
		openPorts = result.OpenPorts
		findingsCount = len(result.Findings)
		servicesCount = len(result.Services)
		endpointsCount = result.Endpoints

		if summary, err := json.Marshal(map[string]int{
			"open_ports":      result.OpenPorts,
			"services_found":  len(result.Services),
			"endpoints_found": result.Endpoints,
			"findings":        len(result.Findings),
			"duration_ms":     int(result.DurationMs),
		}); err == nil {
			if err := rdb.HSet(ctx, model.ResultsKey(prefix, runID), target, string(summary)).Err(); err != nil {
				return fmt.Errorf("write scan summary: %w", err)
			}
		}
		if err := appendFindings(ctx, rdb, model.FindingsKey(prefix, runID), result.Findings); err != nil {
			return err
		}
		if err := appendAssets(ctx, rdb, model.AssetsKey(prefix, runID), result.Services); err != nil {
			return err
		}
	}
	if scanErr != nil {
		failed = 1
	}

	_, err := rdb.Eval(
		ctx,
		finishTargetScript,
		[]string{model.StatusKey(prefix, runID), model.TargetsKey(prefix, runID)},
		target,
		failed,
		openPorts,
		findingsCount,
		servicesCount,
		endpointsCount,
		model.NowUTC().Format(time.RFC3339),
	).Result()
	if err != nil {
		return fmt.Errorf("finish target: %w", err)
	}
	return nil
}

func appendFindings(ctx context.Context, rdb *redis.Client, key string, findings []model.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	values := make([]interface{}, 0, len(findings))
	for _, finding := range findings {
		data, err := json.Marshal(finding)
		if err != nil {
			continue
		}
		values = append(values, string(data))
	}
	if len(values) > 0 {
		if err := rdb.RPush(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("write findings: %w", err)
		}
	}
	return nil
}

func appendAssets(ctx context.Context, rdb *redis.Client, key string, services []model.Service) error {
	if len(services) == 0 {
		return nil
	}
	values := make([]interface{}, 0, len(services))
	for _, service := range services {
		data, err := json.Marshal(service)
		if err != nil {
			continue
		}
		values = append(values, string(data))
	}
	if len(values) > 0 {
		if err := rdb.RPush(ctx, key, values...).Err(); err != nil {
			return fmt.Errorf("write assets: %w", err)
		}
	}
	return nil
}

type WorkerRuntime struct {
	client       *messaging.StreamClient
	rdb          *redis.Client
	rawStream    string
	targetStream string
	group        string
	consumerID   string
	runner       *engine.Runner
	keyPrefix    string
}

func NewWorkerRuntime(rdb *redis.Client, prefix, rawStream, targetStream, group string, runner *engine.Runner) *WorkerRuntime {
	if rawStream == "" {
		rawStream = messaging.DefaultRawStream
	}
	if targetStream == "" {
		targetStream = messaging.DefaultTargetStream
	}
	if group == "" {
		group = messaging.DefaultGroup
	}
	return &WorkerRuntime{
		client:       messaging.NewStreamClient(rdb),
		rdb:          rdb,
		rawStream:    rawStream,
		targetStream: targetStream,
		group:        group,
		consumerID:   fmt.Sprintf("worker-%s", model.NewUUID()[:8]),
		runner:       runner,
		keyPrefix:    prefix,
	}
}

func (w *WorkerRuntime) Run(ctx context.Context) error {
	if err := w.client.CreateGroup(ctx, w.rawStream, w.group); err != nil {
		return fmt.Errorf("create raw stream group: %w", err)
	}
	if err := w.client.CreateGroup(ctx, w.targetStream, w.group); err != nil {
		return fmt.Errorf("create target stream group: %w", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w.runParserLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		w.runScanLoop(ctx)
	}()
	wg.Wait()
	return nil
}

func (w *WorkerRuntime) runParserLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := w.client.ReadGroup(ctx, w.rawStream, w.group, w.consumerID, 1, 2*time.Second)
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, msg := range msgs {
			rawJSON, ok := msg.Values["data"].(string)
			if !ok {
				_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
				continue
			}
			var rawTask model.WorkItem
			if err := json.Unmarshal([]byte(rawJSON), &rawTask); err != nil {
				_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
				continue
			}

			var expandedTargets []string
			for _, targetStr := range rawTask.RawTargets {
				norm := model.ParseTarget(targetStr)
				if norm.Kind == "CIDR" {
					ip, ipnet, err := net.ParseCIDR(norm.Host)
					if err == nil {
						for curr := ip.Mask(ipnet.Mask); ipnet.Contains(curr); incIP(curr) {
							expandedTargets = append(expandedTargets, curr.String())
						}
					}
					continue
				}
				expandedTargets = append(expandedTargets, targetStr)
			}

			w.rdb.HSet(ctx, model.StatusKey(w.keyPrefix, rawTask.ScanRunID),
				"total_targets", len(expandedTargets),
				"status", "running",
			)

			for _, target := range expandedTargets {
				stageInput := model.WorkItem{
					ScanRunID:   rawTask.ScanRunID,
					StageRunID:  model.NewUUID(),
					StageName:   "full_scan",
					Target:      target,
					PortRange:   rawTask.PortRange,
					Policy:      rawTask.Policy,
					PayloadData: rawTask.PayloadData,
				}
				_, _ = w.client.Publish(ctx, w.targetStream, stageInput)
			}
			_ = w.client.Ack(ctx, w.rawStream, w.group, msg.ID)
		}
	}
}

func (w *WorkerRuntime) runScanLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msgs, err := w.client.ReadGroup(ctx, w.targetStream, w.group, w.consumerID, 1, 2*time.Second)
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}

		for _, msg := range msgs {
			rawJSON, ok := msg.Values["data"].(string)
			if !ok {
				_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
				continue
			}
			var input model.WorkItem
			if err := json.Unmarshal([]byte(rawJSON), &input); err != nil {
				_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
				continue
			}

			policy := &input.Policy
			result, scanErr := w.runner.Run(ctx, engine.ScanOptions{
				Targets:      []string{input.Target},
				PortOverride: input.PortRange,
				Policy:       policy,
			})
			if scanErr != nil {
				log.Printf("[Worker] Target scan failed %s: %v\n", input.Target, scanErr)
			}
			if writeErr := writeScanResult(ctx, w.rdb, w.keyPrefix, input.ScanRunID, input.Target, result, scanErr); writeErr != nil {
				log.Printf("[Worker] Failed to persist target result %s: %v\n", input.Target, writeErr)
				continue
			}
			_ = w.client.Ack(ctx, w.targetStream, w.group, msg.ID)
		}
	}
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
