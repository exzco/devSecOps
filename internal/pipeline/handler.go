package pipeline

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"

	"devsecops/internal/config"
	dastModel "devsecops/internal/dast/model"
	dastService "devsecops/internal/dast/service"
	"devsecops/internal/sast/model"
	"devsecops/internal/sast/queue"
	sastService "devsecops/internal/sast/service"
	scaModel "devsecops/internal/sca/model"
	scaSvc "devsecops/internal/sca/service"
)

const (
	ScanTypeSAST = "sast"
	ScanTypeDAST = "dast"
	ScanTypeSCA  = "sca"
)

type Handler struct {
	sastService *sastService.ScanService
	asynqClient *asynq.Client
	dastService *dastService.DastService
	scaService  *scaSvc.ScaService
	scanConfig  *config.ScannerConfig
}

func NewHandler(
	scanService *sastService.ScanService,
	asynqClient *asynq.Client,
	dast *dastService.DastService,
	sca *scaSvc.ScaService,
	scanConfig *config.ScannerConfig,
) *Handler {
	return &Handler{
		sastService: scanService,
		asynqClient: asynqClient,
		dastService: dast,
		scaService:  sca,
		scanConfig:  scanConfig,
	}
}

type SubmitRequest struct {
	Type        string   `json:"type" binding:"required,oneof=sast dast sca"`
	RepoID      uint     `json:"repo_id"`
	Branch      string   `json:"branch"`
	Language    string   `json:"language"`
	QuerySuite  string   `json:"query_suite"`
	RuleProfile string   `json:"rule_profile"`
	Rules       []string `json:"rules"`
	Target      string   `json:"target"`
	Ports       string   `json:"ports"`
	TaskName    string   `json:"task_name"`
}

func (h *Handler) Submit(c *gin.Context) {
	var req SubmitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	switch strings.ToLower(req.Type) {
	case ScanTypeSAST:
		h.submitSAST(c, &req)
	case ScanTypeDAST:
		h.submitDAST(c, &req)
	case ScanTypeSCA:
		h.submitSCA(c, &req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported scan type"})
	}
}

func (h *Handler) submitSAST(c *gin.Context, req *SubmitRequest) {
	if req.RepoID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "repo_id is required for sast scans"})
		return
	}
	if strings.TrimSpace(req.Language) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "language is required for sast scans"})
		return
	}
	if strings.TrimSpace(req.Branch) == "" {
		req.Branch = "main"
	}
	if strings.TrimSpace(req.RuleProfile) == "" {
		req.RuleProfile = h.scanConfig.DefaultProfile
	}

	task, err := h.sastService.CreateTask(
		req.RepoID,
		model.TriggerTypeManual,
		req.Branch,
		req.Language,
		req.QuerySuite,
		req.RuleProfile,
		strings.Join(req.Rules, ","),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create sast task: " + err.Error()})
		return
	}

	asynqTask, err := queue.NewScanRepoTask(req.RepoID, task.ID, h.scanConfig.TimeoutMinutes)
	if err != nil {
		_ = h.sastService.UpdateTaskStatus(task.ID, model.TaskStatusFailed, map[string]interface{}{
			"error_msg": "failed to build queue task: " + err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build queue task: " + err.Error()})
		return
	}

	info, err := h.asynqClient.Enqueue(asynqTask)
	if err != nil {
		_ = h.sastService.UpdateTaskStatus(task.ID, model.TaskStatusFailed, map[string]interface{}{
			"error_msg": "failed to enqueue task: " + err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enqueue task: " + err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "scan submitted",
		"data": gin.H{
			"scan_id":  sastScanID(task.ID),
			"type":     ScanTypeSAST,
			"status":   task.Status,
			"task_id":  task.ID,
			"queue_id": info.ID,
		},
	})
}

func (h *Handler) submitDAST(c *gin.Context, req *SubmitRequest) {
	target := strings.TrimSpace(req.Target)
	if target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required for dast scans"})
		return
	}

	taskID, totalTargets, err := h.dastService.CreateTask(
		c.Request.Context(),
		"",
		req.TaskName,
		target,
		req.Ports,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "scan submitted",
		"data": gin.H{
			"scan_id":       dastScanID(taskID),
			"type":          ScanTypeDAST,
			"status":        "running",
			"task_id":       taskID,
			"total_targets": totalTargets,
		},
	})
}

func (h *Handler) submitSCA(c *gin.Context, req *SubmitRequest) {
	if req.RepoID == 0 && strings.TrimSpace(req.Target) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either repo_id or target directory is required for sca scans"})
		return
	}

	task, err := h.scaService.CreateTask(req.RepoID, req.Branch, req.Language, req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create sca task: " + err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "scan submitted",
		"data": gin.H{
			"scan_id": scaScanID(task.ID),
			"type":    ScanTypeSCA,
			"status":  task.Status,
			"task_id": task.ID,
		},
	})
}

func (h *Handler) GetStatus(c *gin.Context) {
	scanType, taskID, ok := parseScanID(c)
	if !ok {
		return
	}

	switch scanType {
	case ScanTypeSAST:
		id, err := strconv.ParseUint(taskID, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sast scan id"})
			return
		}
		task, err := h.sastService.GetTask(uint(id))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": gin.H{
			"scan_id":     sastScanID(task.ID),
			"type":        ScanTypeSAST,
			"status":      task.Status,
			"task_id":     task.ID,
			"finished":    isSASTTerminal(task.Status),
			"vuln_count":  task.VulnCount,
			"error":       task.ErrorMsg,
			"created_at":  task.CreatedAt,
			"finished_at": task.FinishedAt,
		}})
	case ScanTypeDAST:
		status, err := h.dastService.GetTaskStatus(c.Request.Context(), taskID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": gin.H{
			"scan_id":  dastScanID(taskID),
			"type":     ScanTypeDAST,
			"status":   status["status"],
			"finished": isDASTTerminal(status["status"]),
			"raw":      status,
		}})
	case ScanTypeSCA:
		id, err := strconv.ParseUint(taskID, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sca scan id"})
			return
		}
		task, err := h.scaService.GetTask(uint(id))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "scan not found"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": gin.H{
			"scan_id":     scaScanID(task.ID),
			"type":        ScanTypeSCA,
			"status":      task.Status,
			"task_id":     task.ID,
			"finished":    isSCATerminal(task.Status),
			"total_deps":  task.TotalDeps,
			"vuln_count":  task.VulnCount,
			"error":       task.ErrorMessage,
			"created_at":  task.CreatedAt,
			"finished_at": task.FinishedAt,
		}})
	}
}

func parseScanID(c *gin.Context) (string, string, bool) {
	parts := strings.SplitN(c.Param("id"), ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id must look like sast:<id>, dast:<id>, or sca:<id>"})
		return "", "", false
	}

	scanType := strings.ToLower(strings.TrimSpace(parts[0]))
	if scanType != ScanTypeSAST && scanType != ScanTypeDAST && scanType != ScanTypeSCA {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported scan type"})
		return "", "", false
	}
	return scanType, strings.TrimSpace(parts[1]), true
}

func sastScanID(id uint) string {
	return fmt.Sprintf("%s:%d", ScanTypeSAST, id)
}

func dastScanID(id string) string {
	return fmt.Sprintf("%s:%s", ScanTypeDAST, id)
}

func scaScanID(id uint) string {
	return fmt.Sprintf("%s:%d", ScanTypeSCA, id)
}

func isSASTTerminal(status string) bool {
	switch status {
	case model.TaskStatusSuccess, model.TaskStatusFailed, model.TaskStatusCanceled, model.TaskStatusTimeout:
		return true
	default:
		return false
	}
}

func isDASTTerminal(status string) bool {
	switch status {
	case "completed", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func isSCATerminal(status string) bool {
	switch status {
	case scaModel.TaskStatusSuccess, scaModel.TaskStatusFailed, scaModel.TaskStatusCanceled:
		return true
	default:
		return false
	}
}

func countDASTSeverities(findings []dastModel.Finding) map[string]int {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}
	for _, f := range findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if _, exists := counts[sev]; !exists {
			sev = "info"
		}
		counts[sev]++
	}
	return counts
}
