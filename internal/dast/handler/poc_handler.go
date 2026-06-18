package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"devsecops/internal/dast/service"
	"devsecops/internal/model"
)

type PocHandler struct {
	svc *service.PocService
}

func NewPocHandler(svc *service.PocService) *PocHandler {
	return &PocHandler{svc: svc}
}

func (h *PocHandler) CreatePoc(c *gin.Context) {
	var poc model.PocTemplate
	if err := c.ShouldBindJSON(&poc); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()
	if err := h.svc.CreatePoc(ctx, &poc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC template created successfully",
		"data":    poc,
	})
}

func (h *PocHandler) ListPocs(c *gin.Context) {
	ctx := context.Background()
	pocs, err := h.svc.ListPocs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC templates fetched successfully",
		"data":    pocs,
	})
}

func (h *PocHandler) UpdatePoc(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID format"})
		return
	}

	var req model.PocTemplate
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ID = uint(id)
	ctx := context.Background()
	if err := h.svc.UpdatePoc(ctx, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC template updated successfully",
		"data":    req,
	})
}

func (h *PocHandler) DeletePoc(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ID format"})
		return
	}

	ctx := context.Background()
	if err := h.svc.DeletePoc(ctx, uint(id)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "PoC template deleted successfully",
		"data":    gin.H{"id": id},
	})
}
