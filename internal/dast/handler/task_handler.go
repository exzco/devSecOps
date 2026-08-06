package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"devsecops/internal/dast/service"
)

type DastHandler struct {
	svc *service.DastService
}

func NewDastHandler(svc *service.DastService) *DastHandler {
	return &DastHandler{svc: svc}
}

type CreateDastTaskRequest struct {
	TaskID   string `json:"task_id"`
	TaskName string `json:"task_name"`
	IPs      string `json:"ips" binding:"required"`
	Ports    string `json:"ports"`
}

func (h *DastHandler) CreateTask(c *gin.Context) {
	var req CreateDastTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	taskID, ports, totalIPs, err := h.svc.CreateTask(ctx, req.TaskID, req.TaskName, req.IPs, req.Ports)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST scan task submitted",
		"data": gin.H{
			"task_id":   taskID,
			"total_ips": totalIPs,
			"ports":     ports,
		},
	})
}

func (h *DastHandler) ListTasks(c *gin.Context) {
	tasks, err := h.svc.ListTasks(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST tasks fetched",
		"data":    tasks,
	})
}

func (h *DastHandler) GetTaskStatus(c *gin.Context) {
	taskID := c.Param("id")
	statusMap, err := h.svc.GetTaskStatus(c.Request.Context(), taskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task status fetched",
		"data":    statusMap,
	})
}

func (h *DastHandler) GetTaskResults(c *gin.Context) {
	taskID := c.Param("id")
	findings, err := h.svc.GetTaskResults(c.Request.Context(), taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task results fetched",
		"data":    findings,
	})
}

func (h *DastHandler) DeleteTask(c *gin.Context) {
	taskID := c.Param("id")
	if err := h.svc.DeleteTask(c.Request.Context(), taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task deleted",
		"data":    gin.H{"task_id": taskID},
	})
}

func (h *DastHandler) StopTask(c *gin.Context) {
	taskID := c.Param("id")
	if err := h.svc.StopTask(c.Request.Context(), taskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task stopped",
		"data":    gin.H{"task_id": taskID},
	})
}

func (h *DastHandler) GetTaskAssets(c *gin.Context) {
	taskID := c.Param("id")
	assets, err := h.svc.GetTaskAssets(c.Request.Context(), taskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task assets fetched",
		"data":    assets,
	})
}

type CreateConfigRequest struct {
	ConfigID string `json:"config_id"`
	TaskName string `json:"task_name" binding:"required"`
	IPs      string `json:"ips" binding:"required"`
	Ports    string `json:"ports"`
}

func (h *DastHandler) ListConfigs(c *gin.Context) {
	configs, err := h.svc.ListConfigs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "configs fetched", "data": configs})
}

func (h *DastHandler) CreateConfig(c *gin.Context) {
	var req CreateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.CreateConfig(c.Request.Context(), req.ConfigID, req.TaskName, req.IPs, req.Ports); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "config created"})
}

func (h *DastHandler) DeleteConfig(c *gin.Context) {
	configID := c.Param("id")
	if err := h.svc.DeleteConfig(c.Request.Context(), configID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "config deleted", "data": gin.H{"config_id": configID}})
}

type UpdateConfigRequest struct {
	TaskName string `json:"task_name" binding:"required"`
	IPs      string `json:"ips" binding:"required"`
	Ports    string `json:"ports"`
}

func (h *DastHandler) UpdateConfig(c *gin.Context) {
	configID := c.Param("id")

	var req UpdateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.UpdateConfig(c.Request.Context(), configID, req.TaskName, req.IPs, req.Ports); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "config updated"})
}
