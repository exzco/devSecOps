package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	scaModel "devsecops/internal/sca/model"
	scaService "devsecops/internal/sca/service"
)

type ScaHandler struct {
	svc *scaService.ScaService
}

func NewScaHandler(svc *scaService.ScaService) *ScaHandler {
	return &ScaHandler{svc: svc}
}

func (h *ScaHandler) CreateProject(c *gin.Context) {
	var req scaModel.CreateScaProjectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	proj, err := h.svc.CreateProject(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": proj})
}

func (h *ScaHandler) ListProjects(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))

	projects, total, err := h.svc.ListProjects(c.Request.Context(), page, perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"items":    projects,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		},
	})
}

func (h *ScaHandler) DeleteProject(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project id"})
		return
	}

	if err := h.svc.DeleteProject(c.Request.Context(), uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "deleted successfully"})
}

func (h *ScaHandler) CreateTask(c *gin.Context) {
	var req scaModel.CreateScaScanTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	task, err := h.svc.CreateScanTask(c.Request.Context(), req.ProjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": task})
}

func (h *ScaHandler) ListTasks(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	projectID, _ := strconv.ParseUint(c.Query("project_id"), 10, 64)

	tasks, total, err := h.svc.ListTasks(c.Request.Context(), page, perPage, uint(projectID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"items":    tasks,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		},
	})
}

func (h *ScaHandler) ListDependencies(c *gin.Context) {
	projectID, _ := strconv.ParseUint(c.Query("project_id"), 10, 64)

	deps, err := h.svc.ListDependencies(c.Request.Context(), uint(projectID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "data": deps})
}

func (h *ScaHandler) ListVulnerabilities(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	projectID, _ := strconv.ParseUint(c.Query("project_id"), 10, 64)

	vulns, total, err := h.svc.ListVulnerabilities(c.Request.Context(), page, perPage, uint(projectID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"items":    vulns,
			"total":    total,
			"page":     page,
			"per_page": perPage,
		},
	})
}
