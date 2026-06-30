package handler

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"devsecops/internal/dast/service"
)

type PocHandler struct {
	svc *service.PocService
}

func NewPocHandler(svc *service.PocService) *PocHandler {
	return &PocHandler{svc: svc}
}

type CreatePocRequest struct {
	Name        string   `json:"name" binding:"required"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
	Content     string   `json:"content" binding:"required"`
}

type UpdatePocRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
}

func (h *PocHandler) ListPocs(c *gin.Context) {
	ctx := context.Background()
	pocs, err := h.svc.ListPocs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok", "data": pocs})
}

func (h *PocHandler) CreatePoc(c *gin.Context) {
	var req CreatePocRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Severity == "" {
		req.Severity = "info"
	}

	ctx := context.Background()
	meta, err := h.svc.CreatePoc(ctx, req.Name, req.Description, req.Severity, req.Tags, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "PoC 模板创建成功", "data": meta})
}

func (h *PocHandler) UpdatePoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少模板 ID"})
		return
	}

	var req UpdatePocRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	meta, err := h.svc.UpdatePoc(ctx, id, req.Name, req.Description, req.Severity, req.Tags)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "模板更新成功", "data": meta})
}

func (h *PocHandler) DeletePoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少模板 ID"})
		return
	}

	ctx := context.Background()
	if err := h.svc.DeletePoc(ctx, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "模板已删除", "data": gin.H{"id": id}})
}
