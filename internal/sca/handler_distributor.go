package sca

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"devsecops/internal/model"
)

// ScaHandler SCA 依赖与漏洞分析业务分发器
type ScaHandler struct {
	svc *ScaService
}

func NewScaHandler(svc *ScaService) *ScaHandler {
	return &ScaHandler{svc: svc}
}

// CreateTask handles manual task creation
func (h *ScaHandler) CreateTask(c *gin.Context) {
	var req model.CreateScaTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.svc.CreateTask(req.RepoID, req.Branch, req.Language, req.Target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "sca task created",
		"data":    task,
	})
}

// ListTasks returns paginated tasks
func (h *ScaHandler) ListTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", c.DefaultQuery("page_size", "20")))
	page, perPage = model.NormalizePagination(page, perPage)

	tasks, total, err := h.svc.ListTasks(page, perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"items":     tasks,
			"total":     total,
			"page":      page,
			"page_size": perPage,
		},
	})
}

// GetTask returns details of a single task
func (h *ScaHandler) GetTask(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	task, err := h.svc.GetTask(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": task})
}

// GetDependencies returns dependencies identified in a task
func (h *ScaHandler) GetDependencies(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	deps, err := h.svc.GetTaskDependencies(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": deps})
}

// GetVulnerabilities returns vulnerabilities discovered in a task
func (h *ScaHandler) GetVulnerabilities(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}

	vulns, err := h.svc.GetTaskVulnerabilities(uint(id))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": vulns})
}
