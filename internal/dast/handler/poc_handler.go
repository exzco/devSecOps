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
	Content     string   `json:"content"`
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
	meta, err := h.svc.UpdatePoc(ctx, id, req.Name, req.Description, req.Severity, req.Tags, req.Content)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "模板更新成功", "data": meta})
}

func (h *PocHandler) GetPoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少模板 ID"})
		return
	}

	ctx := context.Background()
	list, err := h.svc.ListPocs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var target *service.PocMeta
	for _, m := range list {
		if m.ID == id {
			target = &m
			break
		}
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "模板不存在"})
		return
	}

	content, err := h.svc.GetPocContent(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "ok",
		"data": gin.H{
			"id":          target.ID,
			"name":        target.Name,
			"description": target.Description,
			"severity":    target.Severity,
			"tags":        target.Tags,
			"file_path":   target.FilePath,
			"created_at":  target.CreatedAt,
			"updated_at":  target.UpdatedAt,
			"content":     content,
		},
	})
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
