package router

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	dastHandler "devsecops/internal/dast/handler"
	"devsecops/internal/pipeline"
	sastHandler "devsecops/internal/sast/handler"
	scaHandler "devsecops/internal/sca/handler"
)

type Handlers struct {
	RepoHandler     *sastHandler.RepoHandler
	ScanHandler     *sastHandler.ScanHandler
	DastCtrlHandler *dastHandler.DastHandler
	ScaHandler      *scaHandler.ScaHandler
	PipelineHandler *pipeline.Handler
	InternalHandler *sastHandler.InternalHandler
}

func SetupRouter(h *Handlers) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		// 统一流水线入口
		v1.POST("/scans", h.PipelineHandler.Submit)
		v1.GET("/scans/:id", h.PipelineHandler.GetStatus)

		// SAST 代码仓库路由
		v1.POST("/repos", h.RepoHandler.CreateRepos)
		v1.GET("/repos", h.RepoHandler.ListRepos)
		v1.PUT("/repos/:id", h.RepoHandler.UpdateRepos)
		v1.DELETE("/repos/:id", h.RepoHandler.DeleteRepos)
		v1.POST("/repos/batch-delete", h.RepoHandler.BatchDeleteRepos)

		// SAST 扫描任务路由
		v1.DELETE("/scan/tasks/:id", h.ScanHandler.DeleteTask)
		v1.GET("/scan/tasks", h.ScanHandler.ListTasks)
		v1.GET("/scan/vulnerabilities", h.ScanHandler.ListVulnerabilities)
		v1.GET("/scan/tasks/:id/logs", h.ScanHandler.GetTaskLogs)
		v1.GET("/scan/tasks/:id/logs/stream", h.ScanHandler.StreamTaskLogs)
		v1.GET("/scan/tasks/:id/sarif", h.ScanHandler.ExportSARIF)
		v1.GET("/scan/tasks/:id/sarif/summary", h.ScanHandler.GetSARIFSummary)

		// DAST 路由
		v1.GET("/dast/scan/tasks", h.DastCtrlHandler.ListTasks)
		v1.GET("/dast/scan/tasks/:id/status", h.DastCtrlHandler.GetTaskStatus)
		v1.GET("/dast/scan/tasks/:id/results", h.DastCtrlHandler.GetTaskResults)
		v1.GET("/dast/scan/tasks/:id/assets", h.DastCtrlHandler.GetTaskAssets)
		v1.DELETE("/dast/scan/tasks/:id", h.DastCtrlHandler.DeleteTask)

		// DAST 扫描配置模板路由
		v1.GET("/dast/scan/configs", h.DastCtrlHandler.ListConfigs)
		v1.POST("/dast/scan/configs", h.DastCtrlHandler.CreateConfig)
		v1.POST("/dast/scan/configs/update/:id", h.DastCtrlHandler.UpdateConfig)
		v1.DELETE("/dast/scan/configs/:id", h.DastCtrlHandler.DeleteConfig)

		// SCA 依赖与漏洞分析路由
		if h.ScaHandler != nil {
			v1.POST("/sca/tasks", h.ScaHandler.CreateTask)
			v1.GET("/sca/tasks", h.ScaHandler.ListTasks)
			v1.GET("/sca/tasks/:id", h.ScaHandler.GetTask)
			v1.GET("/sca/tasks/:id/dependencies", h.ScaHandler.GetDependencies)
			v1.GET("/sca/tasks/:id/vulnerabilities", h.ScaHandler.GetVulnerabilities)
		}
	}

	internal := r.Group("/internal/v1/sast")
	internal.Use(h.InternalHandler.AuthMiddleware())
	{
		internal.GET("/tasks/:id/job", h.InternalHandler.GetJob)
		internal.POST("/tasks/:id/logs", h.InternalHandler.AppendLog)
		internal.POST("/tasks/:id/complete", h.InternalHandler.Complete)
		internal.POST("/tasks/:id/fail", h.InternalHandler.Fail)
	}

	// 静态前端资源挂载
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	r.StaticFile("/icons.svg", "./web/dist/icons.svg")

	r.NoRoute(func(c *gin.Context) {
		path := c.Request.URL.Path
		if path == "/api" || strings.HasPrefix(path, "/api/") ||
			path == "/internal" || strings.HasPrefix(path, "/internal/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File("./web/dist/index.html")
	})

	return r
}
