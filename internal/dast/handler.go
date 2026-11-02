package dast

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DastHandler DAST 动态扫描与配置模板分发器
type DastHandler struct {
	svc *DastService
}

func NewDastHandler(svc *DastService) *DastHandler {
	return &DastHandler{svc: svc}
}

func (h *DastHandler) ListTasks(c *gin.Context) {
	ctx := c.Request.Context()
	tasks, err := h.svc.ListTasks(ctx)
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
	taskId := c.Param("id")
	ctx := c.Request.Context()
	statusMap, err := h.svc.GetTaskStatus(ctx, taskId)
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
	taskId := c.Param("id")
	ctx := c.Request.Context()
	findings, err := h.svc.GetTaskResults(ctx, taskId)
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
	taskId := c.Param("id")
	ctx := c.Request.Context()
	if err := h.svc.DeleteTask(ctx, taskId); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task deleted",
		"data":    gin.H{"task_id": taskId},
	})
}

func (h *DastHandler) GetTaskAssets(c *gin.Context) {
	taskId := c.Param("id")
	ctx := c.Request.Context()
	assets, err := h.svc.GetTaskAssets(ctx, taskId)
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
	ctx := c.Request.Context()
	configs, err := h.svc.ListConfigs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST configs fetched",
		"data":    configs,
	})
}

func (h *DastHandler) CreateConfig(c *gin.Context) {
	var req CreateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	cfg, err := h.svc.CreateConfig(ctx, req.TaskName, req.IPs, req.Ports)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST config created",
		"data":    gin.H{"config_id": cfg.ConfigID},
	})
}

func (h *DastHandler) UpdateConfig(c *gin.Context) {
	configID := c.Param("id")
	var req CreateConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	cfg, err := h.svc.UpdateConfig(ctx, configID, req.TaskName, req.IPs, req.Ports)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST config updated",
		"data":    gin.H{"config_id": cfg.ConfigID},
	})
}

func (h *DastHandler) DeleteConfig(c *gin.Context) {
	configID := c.Param("id")
	ctx := c.Request.Context()
	if err := h.svc.DeleteConfig(ctx, configID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST config deleted",
		"data":    gin.H{"config_id": configID},
	})
}
