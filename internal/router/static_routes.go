package router

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func registerHealthRoute(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func registerStaticRoutes(r *gin.Engine) {
	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/favicon.svg", "./web/dist/favicon.svg")
	r.StaticFile("/icons.svg", "./web/dist/icons.svg")

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			return
		}
		c.File("./web/dist/index.html")
	})
}
