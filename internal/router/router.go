package router

import (
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	dastHandler "devsecops/internal/dast/handler"
	sastHandler "devsecops/internal/sast/handler"
)

type Handlers struct {
	RepoHandler     *sastHandler.RepoHandler
	ScanHandler     *sastHandler.ScanHandler
	DastCtrlHandler *dastHandler.DastHandler
	PocHandler      *dastHandler.PocHandler
}

// SetupRouter 初始化并返回 Gin 引擎及配置的所有路由规则
func SetupRouter(h *Handlers) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		// SAST 代码仓库路由
		v1.POST("/repos", h.RepoHandler.CreateRepos)
		v1.GET("/repos/list", h.RepoHandler.ListRepos)
		v1.POST("/repos/update/:id", h.RepoHandler.UpdateRepos)
		v1.POST("/repos/delete/:id", h.RepoHandler.DeleteRepos)
		v1.POST("/repos/batch-delete", h.RepoHandler.BatchDeleteRepos)

		// SAST 扫描任务路由
		v1.POST("/scan/tasks", h.ScanHandler.CreateTask)
		v1.POST("/scan/tasks/delete/:id", h.ScanHandler.DeleteTask)
		v1.GET("/scan/ListTasks", h.ScanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", h.ScanHandler.ListVulnerabilities)
		v1.GET("/scan/tasks/:id/logs", h.ScanHandler.GetTaskLogs)
		v1.GET("/scan/tasks/:id/logs/stream", h.ScanHandler.StreamTaskLogs)
		v1.GET("/scan/tasks/:id/sarif", h.ScanHandler.ExportSARIF)
		v1.GET("/scan/tasks/:id/sarif/summary", h.ScanHandler.GetSARIFSummary)

		// DAST 路由
		v1.POST("/dast/scan/tasks", h.DastCtrlHandler.CreateTask)
		v1.GET("/dast/scan/tasks", h.DastCtrlHandler.ListTasks)
		v1.GET("/dast/scan/tasks/:id/status", h.DastCtrlHandler.GetTaskStatus)
		v1.GET("/dast/scan/tasks/:id/results", h.DastCtrlHandler.GetTaskResults)
		v1.GET("/dast/scan/tasks/:id/assets", h.DastCtrlHandler.GetTaskAssets)
		v1.POST("/dast/scan/tasks/delete/:id", h.DastCtrlHandler.DeleteTask)
		v1.POST("/dast/scan/tasks/stop/:id", h.DastCtrlHandler.StopTask)

		// DAST 扫描配置模板路由
		v1.GET("/dast/scan/configs", h.DastCtrlHandler.ListConfigs)
		v1.POST("/dast/scan/configs", h.DastCtrlHandler.CreateConfig)
		v1.POST("/dast/scan/configs/update/:id", h.DastCtrlHandler.UpdateConfig)
		v1.POST("/dast/scan/configs/delete/:id", h.DastCtrlHandler.DeleteConfig)

		// DAST PoC 路由
		v1.POST("/dast/pocs", h.PocHandler.CreatePoc)
		v1.GET("/dast/pocs", h.PocHandler.ListPocs)
		v1.GET("/dast/pocs/:id", h.PocHandler.GetPoc)
		v1.POST("/dast/pocs/update/:id", h.PocHandler.UpdatePoc)
		v1.POST("/dast/pocs/delete/:id", h.PocHandler.DeletePoc)
	}

	// 静态前端资源挂载
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	r.StaticFile("/icons.svg", "./web/dist/icons.svg")

	r.NoRoute(func(c *gin.Context) {
		if len(c.Request.URL.Path) >= 4 && c.Request.URL.Path[:4] == "/api" {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File("./web/dist/index.html")
	})

	return r
}
