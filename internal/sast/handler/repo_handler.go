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
	var req model.CreateRepoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
	idStr := c.Param("id")
	id, _ := strconv.ParseUint(idStr, 10, 32)

	var req model.UpdateRepoRequest
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
	idStr := c.Param("id")
	id, _ := strconv.ParseUint(idStr, 10, 32)

	if err := h.repoSvc.Delete(uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "仓库删除成功"})
}

func (h *RepoHandler) BatchDeleteRepos(c *gin.Context) {
	var req model.BatchDeleteReposRequest
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
