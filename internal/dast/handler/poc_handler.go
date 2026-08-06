package handler

import (
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
	pocs, err := h.svc.ListPocs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "ok", "data": pocs})
}

func (h *PocHandler) CreatePoc(c *gin.Context) {
	var req CreatePocRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": err.Error()})
		return
	}
	if req.Severity == "" {
		req.Severity = "info"
	}

	meta, err := h.svc.CreatePoc(c.Request.Context(), req.Name, req.Description, req.Severity, req.Tags, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": -1, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "PoC 模板创建成功", "data": meta})
}

func (h *PocHandler) UpdatePoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": "缺少模板 ID"})
		return
	}

	var req UpdatePocRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": err.Error()})
		return
	}

	meta, err := h.svc.UpdatePoc(c.Request.Context(), id, req.Name, req.Description, req.Severity, req.Tags, req.Content)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": -1, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "模板更新成功", "data": meta})
}

func (h *PocHandler) GetPoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": "缺少模板 ID"})
		return
	}

	meta, content, err := h.svc.GetPocByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": -1, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code":    0,
		"message": "ok",
		"data": gin.H{
			"id":          meta.ID,
			"name":        meta.Name,
			"description": meta.Description,
			"severity":    meta.Severity,
			"tags":        meta.Tags,
			"file_path":   meta.FilePath,
			"created_at":  meta.CreatedAt,
			"updated_at":  meta.UpdatedAt,
			"content":     content,
		},
	})
}

func (h *PocHandler) DeletePoc(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": -1, "error": "缺少模板 ID"})
		return
	}

	if err := h.svc.DeletePoc(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"code": -1, "error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "模板已删除", "data": gin.H{"id": id}})
}
