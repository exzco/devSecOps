package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"

	"devsecops/pkg/logger"
	"devsecops/internal/sast/async"
	"devsecops/internal/sast/model"
	"devsecops/internal/sast/scanner"
	"devsecops/internal/sast/service"
)

type ScanHandler struct {
	scanSvc     *service.ScanService
	asynqClient *asynq.Client
}

func NewScanHandler(svc *service.ScanService, client *asynq.Client) *ScanHandler {
	return &ScanHandler{scanSvc: svc, asynqClient: client}
}

func (h *ScanHandler) CreateTask(c *gin.Context) {
	var req model.CreateScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.scanSvc.CreateTask(
		req.RepoID,
		model.TriggerTypeManual,
		req.Branch,
		req.Language,
		req.QuerySuite,
		req.RuleProfile,
		strings.Join(req.Rules, ","),
		req.UseAIVerification,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan task: " + err.Error()})
		return
	}

	asynqTask, err := async.NewScanRepoTask(req.RepoID, task.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build async task: " + err.Error()})
		return
	}

	info, err := h.asynqClient.Enqueue(asynqTask)
	if err != nil {
		h.scanSvc.UpdateTaskStatus(task.ID, model.TaskStatusFailed, map[string]interface{}{
			"error_msg": "failed to enqueue task: " + err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue task: " + err.Error()})
		return
	}

	logger.SAST("API", "scan task enqueued id=%s, queue=%s", info.ID, info.Queue)

	c.JSON(http.StatusOK, gin.H{
		"message": "scan task submitted",
		"data": gin.H{
			"task_id":  task.ID,
			"queue_id": info.ID,
			"queue":    info.Queue,
		},
	})
}

func (h *ScanHandler) ListTasks(c *gin.Context) {
	var query model.ScanTaskQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.scanSvc.ListTasks(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "scan tasks fetched", "data": result})
}

func (h *ScanHandler) ListVulnerabilities(c *gin.Context) {
	var query model.VulnQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if taskIDStr := c.Query("task_id"); taskIDStr != "" {
		taskID, err := strconv.ParseUint(taskIDStr, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
			return
		}
		query.TaskID = uint(taskID)
	}

	result, err := h.scanSvc.ListVulnerabilities(&query)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "vulnerabilities fetched", "data": result})
}

func (h *ScanHandler) DeleteTask(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	async.CancelTask(taskID)
	if err := h.scanSvc.DeleteTask(taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete task: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "scan task deleted",
		"data":    gin.H{"task_id": taskID},
	})
}

func (h *ScanHandler) ExportSARIF(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if task.SARIFPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not generated yet"})
		return
	}
	if _, err := os.Stat(task.SARIFPath); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not found on disk"})
		return
	}

	filename := fmt.Sprintf("task_%d_results.sarif", task.ID)
	c.FileAttachment(task.SARIFPath, filename)
}

func (h *ScanHandler) GetSARIFSummary(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}
	if task.SARIFPath == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "sarif file not generated yet"})
		return
	}

	data, err := os.ReadFile(task.SARIFPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read sarif file: " + err.Error()})
		return
	}

	var report scanner.SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse sarif json: " + err.Error()})
		return
	}

	parsed, err := scanner.ParseSARIF(task.SARIFPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to normalize sarif: " + err.Error()})
		return
	}

	totalRules := 0
	totalResults := 0
	for _, run := range report.Runs {
		totalRules += len(run.Tool.Driver.Rules)
		totalResults += len(run.Results)
	}

	type ruleHit struct {
		RuleID string `json:"rule_id"`
		Count  int    `json:"count"`
	}
	hitMap := make(map[string]int)
	for _, v := range parsed {
		hitMap[v.RuleID]++
	}
	hits := make([]ruleHit, 0, len(hitMap))
	for id, cnt := range hitMap {
		hits = append(hits, ruleHit{RuleID: id, Count: cnt})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count == hits[j].Count {
			return hits[i].RuleID < hits[j].RuleID
		}
		return hits[i].Count > hits[j].Count
	})
	if len(hits) > 10 {
		hits = hits[:10]
	}

	type vulnSample struct {
		RuleID        string `json:"rule_id"`
		RuleName      string `json:"rule_name"`
		Severity      string `json:"severity"`
		FilePath      string `json:"file_path"`
		StartLine     int    `json:"start_line"`
		Message       string `json:"message"`
		DataFlowSteps int    `json:"data_flow_steps"`
	}
	samples := make([]vulnSample, 0, 5)
	for i, v := range parsed {
		if i >= 5 {
			break
		}
		samples = append(samples, vulnSample{
			RuleID:        v.RuleID,
			RuleName:      v.RuleName,
			Severity:      v.Severity,
			FilePath:      v.FilePath,
			StartLine:     v.StartLine,
			Message:       v.Message,
			DataFlowSteps: len(v.DataFlow),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "sarif summary",
		"data": gin.H{
			"task_id":            task.ID,
			"sarif_path":         task.SARIFPath,
			"schema":             report.Schema,
			"version":            report.Version,
			"runs_count":         len(report.Runs),
			"rules_count":        totalRules,
			"results_count":      totalResults,
			"vuln_count":         len(parsed),
			"top_rule_hits":      hits,
			"vuln_samples":       samples,
			"parse_entrypoint":   "internal/sast/scanner/sarif.go::ParseSARIF",
			"analyze_cmd_origin": "internal/sast/scanner/codeql.go::Analyze",
		},
	})
}

func (h *ScanHandler) GetTaskLogs(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	logs := make([]string, 0, 64)
	if trimmed := strings.TrimSpace(task.ExecutionLog); trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			if item := strings.TrimSpace(line); item != "" {
				logs = append(logs, item)
			}
		}
	}

	if task.ErrorMsg != "" {
		logs = append(logs, "[ERROR] "+task.ErrorMsg)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "task logs fetched",
		"data": gin.H{
			"task_id":     task.ID,
			"status":      task.Status,
			"log_count":   len(logs),
			"logs":        logs,
			"finished_at": task.FinishedAt,
		},
	})
}

func (h *ScanHandler) StreamTaskLogs(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")

	sentCount := 0
	ticker := time.NewTicker(800 * time.Millisecond)
	defer ticker.Stop()

	c.Stream(func(w io.Writer) bool {
		select {
		case <-c.Request.Context().Done():
			return false
		case <-ticker.C:
			task, err := h.scanSvc.GetTask(taskID)
			if err != nil {
				c.SSEvent("error", gin.H{"error": "task not found"})
				return false
			}

			logs := parseNonEmptyLogLines(task.ExecutionLog)

			if task.ErrorMsg != "" {
				logs = append(logs, "[ERROR] "+task.ErrorMsg)
			}

			if sentCount < len(logs) {
				newLogs := logs[sentCount:]
				sentCount = len(logs)
				c.SSEvent("log", gin.H{
					"task_id":    task.ID,
					"status":     task.Status,
					"new_logs":   newLogs,
					"total_logs": sentCount,
				})
			}

			if task.Status == model.TaskStatusSuccess || task.Status == model.TaskStatusFailed || task.Status == model.TaskStatusCanceled || task.Status == model.TaskStatusTimeout {
				c.SSEvent("status", gin.H{
					"task_id":     task.ID,
					"status":      task.Status,
					"finished_at": task.FinishedAt,
					"vuln_count":  task.VulnCount,
					"done":        true,
				})
				return false
			}
			return true
		}
	})
}

func parseTaskIDParam(c *gin.Context) (uint, bool) {
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return 0, false
	}
	return uint(taskID), true
}

// parseNonEmptyLogLines splits raw log text into non-empty trimmed lines.
func parseNonEmptyLogLines(rawLog string) []string {
	trimmed := strings.TrimSpace(rawLog)
	if trimmed == "" {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(trimmed, "\n") {
		if item := strings.TrimSpace(line); item != "" {
			lines = append(lines, item)
		}
	}
	return lines
}
