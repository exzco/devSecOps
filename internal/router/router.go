package router

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	dastHandler "devsecops/internal/dast/handler"
	sastHandler "devsecops/internal/sast/handler"
	scaHandler "devsecops/internal/sca/handler"
)

type Handlers struct {
	RepoHandler     *sastHandler.RepoHandler
	ScanHandler     *sastHandler.ScanHandler
	DastCtrlHandler *dastHandler.DastHandler
	PocHandler      *dastHandler.PocHandler
	ScaHandler      *scaHandler.ScaHandler
	CveAiHandler    *dastHandler.CveAiHandler
}

func SetupRouter(h *Handlers) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	registerHealthRoute(r)

	v1 := r.Group("/api/v1")
	registerSASTRoutes(v1, h)
	registerDASTRoutes(v1, h)
	registerSCARoutes(v1, h)
	registerStaticRoutes(r)

	return r
}
