package router

import "github.com/gin-gonic/gin"

func registerSASTRoutes(v1 *gin.RouterGroup, h *Handlers) {
	v1.POST("/repos", h.RepoHandler.CreateRepos)
	v1.GET("/repos/list", h.RepoHandler.ListRepos)
	v1.POST("/repos/update/:id", h.RepoHandler.UpdateRepos)
	v1.POST("/repos/delete/:id", h.RepoHandler.DeleteRepos)
	v1.POST("/repos/batch-delete", h.RepoHandler.BatchDeleteRepos)

	v1.POST("/scan/tasks", h.ScanHandler.CreateTask)
	v1.POST("/scan/tasks/delete/:id", h.ScanHandler.DeleteTask)
	v1.GET("/scan/ListTasks", h.ScanHandler.ListTasks)
	v1.GET("/scan/vulnerabilities", h.ScanHandler.ListVulnerabilities)
	v1.GET("/scan/tasks/:id/logs", h.ScanHandler.GetTaskLogs)
	v1.GET("/scan/tasks/:id/logs/stream", h.ScanHandler.StreamTaskLogs)
	v1.GET("/scan/tasks/:id/sarif", h.ScanHandler.ExportSARIF)
	v1.GET("/scan/tasks/:id/sarif/summary", h.ScanHandler.GetSARIFSummary)
}

func registerDASTRoutes(v1 *gin.RouterGroup, h *Handlers) {
	v1.POST("/dast/scan/tasks", h.DastCtrlHandler.CreateTask)
	v1.GET("/dast/scan/tasks", h.DastCtrlHandler.ListTasks)
	v1.GET("/dast/scan/tasks/:id/status", h.DastCtrlHandler.GetTaskStatus)
	v1.GET("/dast/scan/tasks/:id/results", h.DastCtrlHandler.GetTaskResults)
	v1.GET("/dast/scan/tasks/:id/assets", h.DastCtrlHandler.GetTaskAssets)
	v1.POST("/dast/scan/tasks/delete/:id", h.DastCtrlHandler.DeleteTask)
	v1.POST("/dast/scan/tasks/stop/:id", h.DastCtrlHandler.StopTask)

	v1.GET("/dast/scan/configs", h.DastCtrlHandler.ListConfigs)
	v1.POST("/dast/scan/configs", h.DastCtrlHandler.CreateConfig)
	v1.POST("/dast/scan/configs/update/:id", h.DastCtrlHandler.UpdateConfig)
	v1.POST("/dast/scan/configs/delete/:id", h.DastCtrlHandler.DeleteConfig)

	v1.GET("/dast/cve/list", h.CveAiHandler.GetLocalCves)
	v1.GET("/dast/cve/fetch", h.CveAiHandler.FetchCves)
	v1.POST("/dast/pocs/generate-ai", h.CveAiHandler.GenerateAiPoc)

	v1.POST("/dast/pocs", h.PocHandler.CreatePoc)
	v1.GET("/dast/pocs", h.PocHandler.ListPocs)
	v1.GET("/dast/pocs/:id", h.PocHandler.GetPoc)
	v1.POST("/dast/pocs/update/:id", h.PocHandler.UpdatePoc)
	v1.POST("/dast/pocs/delete/:id", h.PocHandler.DeletePoc)
}

func registerSCARoutes(v1 *gin.RouterGroup, h *Handlers) {
	if h.ScaHandler == nil {
		return
	}
	v1.POST("/sca/projects", h.ScaHandler.CreateProject)
	v1.GET("/sca/projects", h.ScaHandler.ListProjects)
	v1.POST("/sca/projects/delete/:id", h.ScaHandler.DeleteProject)

	v1.POST("/sca/tasks", h.ScaHandler.CreateTask)
	v1.GET("/sca/tasks", h.ScaHandler.ListTasks)
	v1.GET("/sca/dependencies", h.ScaHandler.ListDependencies)
	v1.GET("/sca/vulnerabilities", h.ScaHandler.ListVulnerabilities)
}

