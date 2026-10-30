package handler

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"devsecops/internal/sast/contract"
	"devsecops/internal/sast/model"
	"devsecops/internal/sast/service"
)

type InternalHandler struct {
	scanSvc     *service.ScanService
	workerToken string
	workDir     string
}

func NewInternalHandler(scanSvc *service.ScanService, workerToken, workDir string) *InternalHandler {
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
	if task.Status == model.TaskStatusCanceled {
		c.JSON(http.StatusConflict, gin.H{"error": "task was canceled"})
		return
	}
	if task.Status != model.TaskStatusPending && task.Status != model.TaskStatusRunning {
		c.JSON(http.StatusConflict, gin.H{"error": "task is already finished", "status": task.Status})
		return
	}

	now := time.Now()
	if task.Status == model.TaskStatusPending {
		if err := h.scanSvc.UpdateTaskStatus(taskID, model.TaskStatusRunning, map[string]interface{}{
			"started_at":    now,
			"execution_log": fmt.Sprintf("[%s] 任务已开始执行\n", now.Format("2006-01-02 15:04:05")),
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start task"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"data": contract.Job{
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
	var req contract.Callback
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "message is required"})
		return
	}
	if err := h.scanSvc.AppendTaskLog(taskID, req.Message); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to append task log"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *InternalHandler) Complete(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64<<20)
	taskID, ok := parseTaskIDParam(c)
	if !ok {
		return
	}

	task, err := h.scanSvc.GetTask(taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	var req contract.Callback
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
	var req contract.Callback
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Error == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "error is required"})
		return
	}

	finishedAt := time.Now()
	if err := h.scanSvc.UpdateTaskStatus(taskID, model.TaskStatusFailed, map[string]interface{}{
		"finished_at": finishedAt,
		"duration_ms": req.DurationMs,
		"commit_sha":  req.CommitSHA,
		"worker_id":   req.WorkerID,
		"error_msg":   req.Error,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to finalize task"})
		return
	}
	_ = h.scanSvc.AppendTaskLog(taskID, "扫描任务失败: "+req.Error)
	c.Status(http.StatusNoContent)
}
