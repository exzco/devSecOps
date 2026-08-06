package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	dastService "devsecops/internal/dast/service"
)

type CveAiHandler struct {
	svc *dastService.CveAiService
}

func NewCveAiHandler(svc *dastService.CveAiService) *CveAiHandler {
	return &CveAiHandler{svc: svc}
}

// GetLocalCves handles GET /api/v1/dast/cve/list (Queries local DB / Redis ONLY. Fast response, zero network calls!)
func (h *CveAiHandler) GetLocalCves(c *gin.Context) {
	keyword := c.Query("keyword")
	year, _ := strconv.Atoi(c.DefaultQuery("year", "2025"))

	cves, err := h.svc.GetLocalCves(c.Request.Context(), keyword, year)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": cves,
	})
}

// FetchCves handles GET /api/v1/dast/cve/fetch (Explicit online fetch or local query when local=true)
func (h *CveAiHandler) FetchCves(c *gin.Context) {
	keyword := c.Query("keyword")
	year, _ := strconv.Atoi(c.DefaultQuery("year", "2025"))
	localOnly := c.Query("local") == "true" || c.Query("local_only") == "true"

	if localOnly {
		cves, err := h.svc.GetLocalCves(c.Request.Context(), keyword, year)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"data": cves,
		})
		return
	}

	cves, err := h.svc.SyncOnlineCves(c.Request.Context(), keyword, year)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": cves,
	})
}

func (h *CveAiHandler) GenerateAiPoc(c *gin.Context) {
	var req dastService.GeneratePocRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	poc, err := h.svc.GenerateAiPoc(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": poc,
	})
}
