package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"devsecops/internal/sast/model"
	"devsecops/internal/sast/service"
)

type RepoHandler struct {
	repoSvc *service.RepoService
}

func NewRepoHandler(repoSvc *service.RepoService) *RepoHandler {
	return &RepoHandler{
		repoSvc: repoSvc,
	}
}

func (h *RepoHandler) CreateRepos(c *gin.Context) {
	var req model.RepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name == "" || req.URL == "" || req.Language == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name, url and language are required"})
		return
	}

	repo, err := h.repoSvc.Create(&req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "仓库创建成功", "data": repo})
}

func (h *RepoHandler) ListRepos(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))

	result, err := h.repoSvc.List(page, perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "仓库列表获取成功", "data": result})
}

func (h *RepoHandler) UpdateRepos(c *gin.Context) {
	id, ok := parseRepoID(c)
	if !ok {
		return
	}

	var req model.RepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	repo, err := h.repoSvc.Update(uint(id), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "仓库更新成功", "data": repo})
}

func (h *RepoHandler) DeleteRepos(c *gin.Context) {
	id, ok := parseRepoID(c)
	if !ok {
		return
	}

	if err := h.repoSvc.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "仓库删除成功"})
}

func parseRepoID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid repository id"})
		return 0, false
	}
	return uint(id), true
}

func (h *RepoHandler) BatchDeleteRepos(c *gin.Context) {
	var req struct {
		IDs []uint `json:"ids" binding:"required,min=1"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.repoSvc.DeleteBatch(req.IDs); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "仓库批量删除成功",
		"data":    gin.H{"deleted": len(req.IDs)},
	})
}
