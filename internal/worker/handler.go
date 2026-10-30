package worker

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type WorkerHandler struct {
	rdb *redis.Client
}

func NewWorkerHandler(rdb *redis.Client) *WorkerHandler {
	return &WorkerHandler{rdb: rdb}
}

func (h *WorkerHandler) GetOverview(c *gin.Context) {
	overview, err := GetWorkersOverview(c.Request.Context(), h.rdb)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get workers overview: " + err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "workers overview fetched",
		"data":    overview,
	})
}
