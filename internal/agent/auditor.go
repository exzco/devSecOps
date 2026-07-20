package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sashabaranov/go-openai"
)

const systemPrompt = `你是一名顶级应用安全专家（AppSec Expert）与代码审计大师。
你的任务是对 SAST（静态代码分析）识别到的潜在漏洞进行深度的 LLM 语义分析与误报研判，并提供专业的修复建议与测试指引。

[执行约束]
1. 输出格式：必须仅输出一段合法的 JSON，不要输出任何 Markdown 包裹（即不要有 '''json），JSON 结构必须严格遵守：
   {
     "is_false_positive": false,
     "confidence": "High",
     "vulnerability_analysis": "对漏洞成因、数据流传播过程及可利用性的详细深度分析说明",
     "remediation_suggestion": "针对性的安全修复方案，并附上修复后的标准代码片段",
     "manual_poc": "安全人员手动复现/验证该漏洞的 HTTP 请求示例或 curl 命令（仅供测试验证）"
   }
2. 误报研判逻辑 (is_false_positive)：
   - 仔细审查提供的代码片段及上下文。如果代码中已经包含了有效的输入净化、消毒、类型转换或安全过滤逻辑（如使用了安全的 API、参数化查询等），请将 "is_false_positive" 标记为 true。
   - 如果代码确实存在安全隐患且数据流可控，标记为 false。
3. 置信度评估 (confidence)：
   - 可选值: "High", "Medium", "Low"。
4. 无害化限制：仅用于软件安全防御、代码研判与安全修复指导。`

// AuditorConfig represents the configuration for the AppSec Auditor.
type AuditorConfig struct {
	APIKey  string
	BaseURL string // Default: https://api.deepseek.com/v1
	Model   string // Default: deepseek-chat
}

// AppSecAuditor is the engine that interacts with the LLM API.
type AppSecAuditor struct {
	client *openai.Client
	model  string
}

// NewAppSecAuditor initializes a new AppSecAuditor with the given config.
func NewAppSecAuditor(cfg AuditorConfig) *AppSecAuditor {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.deepseek.com"
	}
	if !strings.HasSuffix(cfg.BaseURL, "/v1") && !strings.Contains(cfg.BaseURL, "/v1/") {
		cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/") + "/v1"
	}
	if cfg.Model == "" {
		cfg.Model = "deepseek-chat"
	}

	config := openai.DefaultConfig(cfg.APIKey)
	config.BaseURL = cfg.BaseURL
	client := openai.NewClientWithConfig(config)

	return &AppSecAuditor{
		client: client,
		model:  cfg.Model,
	}
}

// AIAuditResult holds the LLM semantic evaluation of a SAST finding.
type AIAuditResult struct {
	IsFalsePositive       bool   `json:"is_false_positive"`
	Confidence            string `json:"confidence"`
	VulnerabilityAnalysis string `json:"vulnerability_analysis"`
	RemediationSuggestion string `json:"remediation_suggestion"`
	ManualPoC             string `json:"manual_poc"`
}

// AnalyzeVulnerability performs pure LLM semantic auditing for a SAST finding.
func (a *AppSecAuditor) AnalyzeVulnerability(ctx context.Context, vulnType, language, projectDesc, codeContext string) (*AIAuditResult, error) {
	return a.AnalyzeVulnerabilityWithLogger(ctx, vulnType, language, projectDesc, codeContext, nil)
}

// AnalyzeVulnerabilityWithLogger performs LLM semantic auditing and supports real-time logging.
func (a *AppSecAuditor) AnalyzeVulnerabilityWithLogger(ctx context.Context, vulnType, language, projectDesc, codeContext string, logFn func(string)) (*AIAuditResult, error) {
	if logFn == nil {
		logFn = func(string) {}
	}

	logFn(fmt.Sprintf("[AI-Audit] 发起 SAST 漏洞语义分析 (类型: %s, 语言: %s)...", vulnType, language))

	userPrompt := fmt.Sprintf(`请对以下 SAST 识别到的漏洞进行语义分析与误报研判：

[目标信息]
- 漏洞类型: %s
- 技术栈: %s
- 项目上下文: %s

[受影响代码及上下文]
%s

请严格按照要求的 JSON 结构输出语义分析、误报研判、修复建议及手动复现指引。`, vulnType, language, projectDesc, codeContext)

	req := openai.ChatCompletionRequest{
		Model: a.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userPrompt},
		},
		Temperature: 0.1,
	}

	resp, err := a.client.CreateChatCompletion(ctx, req)
	if err != nil {
		logFn(fmt.Sprintf("[AI-Audit-ERROR] AI API 请求失败: %v", err))
		return nil, fmt.Errorf("failed to analyze vulnerability: %w", err)
	}

	rawContent := resp.Choices[0].Message.Content
	cleanedContent := cleanJSONOutput(rawContent)

	var result AIAuditResult
	if err := json.Unmarshal([]byte(cleanedContent), &result); err != nil {
		logFn(fmt.Sprintf("[AI-Audit-ERROR] JSON 解析失败: %v. Raw: %s", err, rawContent))
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}

	logFn(fmt.Sprintf("[AI-Audit] 语义分析完成！是否误报: %v, 置信度: %s", result.IsFalsePositive, result.Confidence))
	return &result, nil
}

func cleanJSONOutput(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```json") {
		raw = strings.TrimPrefix(raw, "```json")
	} else if strings.HasPrefix(raw, "```") {
		raw = strings.TrimPrefix(raw, "```")
	}
	if strings.HasSuffix(raw, "```") {
		raw = strings.TrimSuffix(raw, "```")
	}
	return strings.TrimSpace(raw)
}
