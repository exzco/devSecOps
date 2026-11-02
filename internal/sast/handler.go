package sast

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"devsecops/internal/model"
)

// 1. 代码仓库 CRUD 分发器 (RepoHandler)

type RepoHandler struct {
	repoSvc *RepoService
}

func NewRepoHandler(repoSvc *RepoService) *RepoHandler {
	return &RepoHandler{repoSvc: repoSvc}
}

func (h *RepoHandler) CreateRepos(c *gin.Context) {
	var req model.RepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" || req.URL == "" || req.Language == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, url and language are required"})
		return
	}

	repo, err := h.repoSvc.Create(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "仓库创建成功", "data": repo})
}

func (h *RepoHandler) ListRepos(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))

	result, err := h.repoSvc.List(page, perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "仓库列表获取成功", "data": result})
}

func (h *RepoHandler) UpdateRepos(c *gin.Context) {
	id, ok := parseRepoID(c)
	if !ok {
		return
	}

	var req model.RepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	repo, err := h.repoSvc.Update(id, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "仓库更新成功", "data": repo})
}

func (h *RepoHandler) DeleteRepos(c *gin.Context) {
	id, ok := parseRepoID(c)
	if !ok {
		return
	}

	if err := h.repoSvc.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "仓库删除成功"})
}

func (h *RepoHandler) BatchDeleteRepos(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repoSvc.DeleteBatch(req.IDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "仓库批量删除成功",
		"data":    gin.H{"deleted": len(req.IDs)},
	})
}

// 2. 扫描任务与漏洞查询分发器 (ScanHandler)

type ScanHandler struct {
	scanSvc *ScanService
}

func NewScanHandler(svc *ScanService) *ScanHandler {
	return &ScanHandler{scanSvc: svc}
}

func (h *ScanHandler) ListTasks(c *gin.Context) {
	var query model.ListQuery
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
	var query model.ListQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
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

	force := c.Query("force") == "true" || c.Query("force") == "1"

	if err := h.scanSvc.DeleteTask(taskID, force); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "failed to delete task: " + err.Error()})
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

	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse sarif json: " + err.Error()})
		return
	}

	parsed, err := ParseSARIFData(data)
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

	logs := extractLogLines(task.ExecutionLog, task.ErrorMsg)

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

			logs := extractLogLines(task.ExecutionLog, task.ErrorMsg)

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

// 3. Worker 内部通信分发器 (InternalHandler)

type InternalHandler struct {
	scanSvc     *ScanService
	workerToken string
	workDir     string
}

func NewInternalHandler(scanSvc *ScanService, workerToken, workDir string) *InternalHandler {
	return &InternalHandler{
		scanSvc:     scanSvc,
		workerToken: workerToken,
		workDir:     workDir,
	}
}

func (h *InternalHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := c.GetHeader("X-Worker-Token")
		if h.workerToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(h.workerToken)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid worker token"})
			return
		}
		c.Next()
	}
}

func (h *InternalHandler) GetJob(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	workerID := c.Query("worker_id")
	if workerID == "" {
		workerID = c.GetHeader("X-Worker-ID")
	}

	updates := map[string]interface{}{}
	if task.Status == model.TaskStatusPending {
		updates["started_at"] = time.Now()
	}
	if workerID != "" {
		updates["worker_id"] = workerID
	}
	if len(updates) > 0 {
		if err := h.scanSvc.UpdateTaskStatus(taskID, model.TaskStatusRunning, updates); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start task"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": Job{
		TaskID:      task.ID,
		RepoID:      task.RepoID,
		RepoURL:     task.Repository.URL,
		Branch:      task.Branch,
		Language:    task.Language,
		AuthType:    task.Repository.AuthType,
		AuthSecret:  task.Repository.AuthSecret,
		QuerySuite:  task.QuerySuite,
		RuleProfile: task.RuleProfile,
		Rules:       task.Rules,
	}})
}

func (h *InternalHandler) AppendLog(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}
	var req Callback
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message is required"})
		return
	}

	workerID := c.GetHeader("X-Worker-ID")
	if workerID != "" {
		_ = h.scanSvc.UpdateTask(taskID, map[string]interface{}{"worker_id": workerID})
	}

	if err := h.scanSvc.AppendTaskLog(taskID, req.Message); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to append task log"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InternalHandler) Complete(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256<<20)
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	var req Callback
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.SARIF) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sarif is required"})
		return
	}

	sarifPath := filepath.Join(h.workDir, strconv.FormatUint(uint64(taskID), 10), "results.sarif")
	if err := os.MkdirAll(filepath.Dir(sarifPath), 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create report directory"})
		return
	}
	if err := os.WriteFile(sarifPath, req.SARIF, 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist SARIF report"})
		return
	}

	if err := h.scanSvc.SaveResults(task.RepoID, taskID, task.Repository.URL, req.Vulnerabilities); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save scan results: " + err.Error()})
		return
	}

	finishedAt := time.Now()
	duration := req.DurationMs
	if duration <= 0 && task.StartedAt != nil {
		duration = finishedAt.Sub(*task.StartedAt).Milliseconds()
	}
	if err := h.scanSvc.UpdateTaskStatus(taskID, model.TaskStatusSuccess, map[string]interface{}{
		"finished_at": finishedAt,
		"duration_ms": duration,
		"commit_sha":  req.CommitSHA,
		"worker_id":   req.WorkerID,
		"sarif_path":  sarifPath,
		"vuln_count":  len(req.Vulnerabilities),
		"error_msg":   "",
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to finalize task"})
		return
	}
	_ = h.scanSvc.AppendTaskLog(taskID, fmt.Sprintf("任务执行成功，共 %d 条漏洞，耗时 %dms", len(req.Vulnerabilities), duration))
	c.Status(http.StatusNoContent)
}

func (h *InternalHandler) Fail(c *gin.Context) {
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}
	var req Callback
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Error == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error is required"})
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	finishedAt := time.Now()
	duration := req.DurationMs
	if duration <= 0 && task.StartedAt != nil {
		duration = finishedAt.Sub(*task.StartedAt).Milliseconds()
	}
	if err := h.scanSvc.UpdateTaskStatus(taskID, model.TaskStatusFailed, map[string]interface{}{
		"finished_at": finishedAt,
		"duration_ms": duration,
		"commit_sha":  req.CommitSHA,
		"worker_id":   req.WorkerID,
		"error_msg":   req.Error,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record task failure"})
		return
	}
	_ = h.scanSvc.AppendTaskLog(taskID, fmt.Sprintf("任务执行失败: %s", req.Error))
	c.Status(http.StatusNoContent)
}

// 4. 辅助函数

func parseRepoID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repository id"})
		return 0, false
	}
	return uint(id), true
}

func parseTaskIDParam(c *gin.Context) (uint, bool) {
	taskID, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return 0, false
	}
	return uint(taskID), true
}

func extractLogLines(executionLog, errorMsg string) []string {
	logs := make([]string, 0, 64)
	if trimmed := strings.TrimSpace(executionLog); trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			if item := strings.TrimSpace(line); item != "" {
				logs = append(logs, item)
			}
		}
	}
	if trimmed := strings.TrimSpace(errorMsg); trimmed != "" {
		logs = append(logs, "[ERROR] "+trimmed)
	}
	return logs
}
