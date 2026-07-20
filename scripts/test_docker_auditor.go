package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"devsecops/internal/agent"
	"devsecops/internal/config"
)

func main() {
	fmt.Println("=== 正在单独测试 AI SAST 语义分析与误报研判功能 ===")

	// 尝试从配置文件读取真实配置
	if _, err := config.LoadConfig("configs/config.local.yaml"); err != nil {
		log.Printf("读取本地配置失败，降级使用环境变量: %v", err)
	}

	apiKey := ""
	baseURL := ""
	modelName := ""
	if config.GlobalConfig != nil && config.GlobalConfig.OpenAI.APIKey != "" {
		apiKey = config.GlobalConfig.OpenAI.APIKey
		baseURL = config.GlobalConfig.OpenAI.BaseURL
		modelName = config.GlobalConfig.OpenAI.Model
	}

	if apiKey == "" || apiKey == "your_deepseek_api_key_here" {
		log.Fatal("错误: 未配置有效的 APIKey，请在 configs/config.local.yaml 或环境变量 DEEPSEEK_API_KEY 中配置。")
	}

	auditor := agent.NewAppSecAuditor(agent.AuditorConfig{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Model:   modelName,
	})

	// 模拟一个包含 Path Traversal 漏洞的代码上下文
	sampleVulnType := "Path Traversal (路径穿越)"
	sampleFramework := "Go / Gin"
	sampleCodeCtx := `
package main

import (
	"net/http"
	"os"
	"path/filepath"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/read", func(c *gin.Context) {
		filename := c.Query("file")
		// 存在漏洞的代码：直接将用户输入与 /tmp 目录拼接，未清洗 ../
		targetPath := filepath.Join("/tmp", filename)
		content, err := os.ReadFile(targetPath)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.String(http.StatusOK, string(content))
	})
	r.Run(":8080")
}
`

	logFn := func(msg string) {
		fmt.Printf("\n[测试日志] %s\n", msg)
	}

	ctx := context.Background()
	sampleProjectDesc := "一个基于 Gin 的简单文件下载/读取服务，用于提供临时文件的访问功能"
	res, err := auditor.AnalyzeVulnerabilityWithLogger(ctx, sampleVulnType, sampleFramework, sampleProjectDesc, sampleCodeCtx, logFn)
	if err != nil {
		log.Fatalf("AI 漏洞语义分析测试失败: %v", err)
	}

	resJSON, _ := json.MarshalIndent(res, "", "  ")
	fmt.Printf("\n=================== 测试总结报告 ===================\n")
	fmt.Printf("AI 语义分析与误报研判输出:\n%s\n", string(resJSON))
	fmt.Println("====================================================")
}
