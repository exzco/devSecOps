package internal

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"devsecops/internal/dast"
	"devsecops/internal/pipeline"
	"devsecops/internal/sast"
	"devsecops/internal/sca"
	"devsecops/internal/worker"
)

type Handlers struct {
	RepoHandler     *sast.RepoHandler
	ScanHandler     *sast.ScanHandler
	DastCtrlHandler *dast.DastHandler
	ScaHandler      *sca.ScaHandler
	PipelineHandler *pipeline.Handler
	InternalHandler *sast.InternalHandler
	WorkerHandler   *worker.WorkerHandler
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

		if h.WorkerHandler != nil {
			v1.GET("/workers", h.WorkerHandler.GetOverview)
		}
	}

	internalGroup := r.Group("/internal/v1/sast")
	internalGroup.Use(h.InternalHandler.AuthMiddleware())
	{
		internalGroup.GET("/tasks/:id/job", h.InternalHandler.GetJob)
		internalGroup.POST("/tasks/:id/logs", h.InternalHandler.AppendLog)
		internalGroup.POST("/tasks/:id/complete", h.InternalHandler.Complete)
		internalGroup.POST("/tasks/:id/fail", h.InternalHandler.Fail)
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
