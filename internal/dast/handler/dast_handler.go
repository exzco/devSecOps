package handler

import (
	"context"
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
	TaskID string `json:"task_id"`
	IPs    string `json:"ips" binding:"required"`
	Ports  string `json:"ports"`
}

func (h *DastHandler) CreateTask(c *gin.Context) {
	var req CreateDastTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	taskID, totalIPs, err := h.svc.CreateTask(ctx, req.TaskID, req.IPs, req.Ports)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST scan task submitted",
		"data": gin.H{
			"task_id":   taskID,
			"total_ips": totalIPs,
			"ports":     req.Ports,
		},
	})
}

func (h *DastHandler) ListTasks(c *gin.Context) {
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
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
	ctx := context.Background()
	_ = h.svc.DeleteTask(ctx, taskId)

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task deleted",
		"data":    gin.H{"task_id": taskId},
	})
}

func (h *DastHandler) StopTask(c *gin.Context) {
	taskId := c.Param("id")
	ctx := context.Background()
	if err := h.svc.StopTask(ctx, taskId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "DAST task stopped",
		"data":    gin.H{"task_id": taskId},
	})
}

func (h *DastHandler) GetTaskAssets(c *gin.Context) {
	taskId := c.Param("id")
	ctx := context.Background()
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

