package main

import (
    "github.com/gin-gonic/gin"
    "net/http"
    "os"
    "path/filepath"
)

func main() {
    r := gin.Default()
    r.GET("/read", func(c *gin.Context) {
        filename := c.Query("file")
        path := filepath.Join("/tmp", filename)
        data, err := os.ReadFile(path)
        if err != nil {
            c.String(http.StatusInternalServerError, err.Error())
            return
        }
        c.String(http.StatusOK, string(data))
    })
    r.Run(":8080")
}
