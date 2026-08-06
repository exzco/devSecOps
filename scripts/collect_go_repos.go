package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"devsecops/pkg/logger"
)

type Config struct {
	BackendURL       string `json:"backend_url"`
	GitHubToken      string `json:"github_token"`
	LLMAPIKey        string `json:"llm_api_key"`
	LLMBaseURL       string `json:"llm_base_url"`
	LLMModel         string `json:"llm_model"`
	MinStars         int    `json:"min_stars"`
	MaxReposPerQuery int    `json:"max_repos_per_query"`
	QuerySuite       string `json:"query_suite"`
	UseAIVerification bool  `json:"use_ai_verification"`
	MacroGoal        string `json:"macro_goal"`
}

type SubTask struct {
	SubTaskID     int      `json:"subtask_id"`
	Title         string   `json:"title"`
	Description   string   `json:"description,omitempty"`
	SearchQuery   string   `json:"search_query"`
	FocusCVETypes []string `json:"focus_cve_types"`
}

type EvaluationResult struct {
	Score              int    `json:"score"`
	Reason             string `json:"reason"`
	RecommendedProfile string `json:"recommended_profile"`
}

type GitHubRepoItem struct {
	Name            string   `json:"name"`
	FullName        string   `json:"full_name"`
	HTMLURL         string   `json:"html_url"`
	CloneURL        string   `json:"clone_url"`
	StargazersCount int      `json:"stargazers_count"`
	DefaultBranch   string   `json:"default_branch"`
	Description     string   `json:"description"`
	Topics          []string `json:"topics"`
}

type GitHubSearchResponse struct {
	Items   []GitHubRepoItem `json:"items"`
	Message string           `json:"message,omitempty"`
}

func loadConfig(configPath string) Config {
	cfg := Config{
		BackendURL:       "http://localhost:22211",
		GitHubToken:      os.Getenv("GITHUB_TOKEN"),
		LLMAPIKey:        os.Getenv("DEEPSEEK_API_KEY"),
		LLMBaseURL:       "https://api.deepseek.com",
		LLMModel:         "deepseek-chat",
		MinStars:         20,
		MaxReposPerQuery: 10,
		UseAIVerification: true,
		MacroGoal:        "搜集正在活跃维护、具备真实业务逻辑的 Go 语言开源应用与组件 (如 CMS、管理后台、API 网关、微服务平台、文件传输系统)，筛选具备 0-day 漏洞挖掘价值与 CVE 申请潜力的目标",
	}

	if envKey := os.Getenv("OPENAI_API_KEY"); envKey != "" && cfg.LLMAPIKey == "" {
		cfg.LLMAPIKey = envKey
	}
	if envBase := os.Getenv("OPENAI_BASE_URL"); envBase != "" {
		cfg.LLMBaseURL = envBase
	}
	if envModel := os.Getenv("OPENAI_MODEL"); envModel != "" {
		cfg.LLMModel = envModel
	}

	if configPath != "" && fileExists(configPath) {
		data, err := os.ReadFile(configPath)
		if err == nil {
			var jsonCfg Config
			if err := json.Unmarshal(data, &jsonCfg); err == nil {
				if jsonCfg.BackendURL != "" {
					cfg.BackendURL = jsonCfg.BackendURL
				}
				if jsonCfg.GitHubToken != "" {
					cfg.GitHubToken = jsonCfg.GitHubToken
				}
				if jsonCfg.LLMAPIKey != "" {
					cfg.LLMAPIKey = jsonCfg.LLMAPIKey
				}
				if jsonCfg.LLMBaseURL != "" {
					cfg.LLMBaseURL = jsonCfg.LLMBaseURL
				}
				if jsonCfg.LLMModel != "" {
					cfg.LLMModel = jsonCfg.LLMModel
				}
				if jsonCfg.MaxReposPerQuery > 0 {
					cfg.MaxReposPerQuery = jsonCfg.MaxReposPerQuery
				}
				if jsonCfg.MacroGoal != "" {
					cfg.MacroGoal = jsonCfg.MacroGoal
				}
			}
		}
	}

	return cfg
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func httpRequest(reqURL, method string, headers map[string]string, body []byte, timeoutSec int) (int, []byte, error) {
	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	var reqBody io.Reader
	if len(body) > 0 {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, reqURL, reqBody)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("User-Agent", "DevSecOps-Go-Collector/1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	return resp.StatusCode, respData, err
}

func normalizeGitURL(raw string) string {
	u := strings.TrimSpace(strings.ToLower(raw))
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimRight(u, "/")
	if strings.HasPrefix(u, "git@github.com:") {
		u = "https://github.com/" + strings.TrimPrefix(u, "git@github.com:")
	}
	return u
}

func sanitizeGitHubQuery(raw string) string {
	q := strings.TrimSpace(raw)
	q = strings.ReplaceAll(q, `"`, "")
	q = strings.ReplaceAll(q, `'`, "")
	if !strings.Contains(strings.ToLower(q), "language:go") {
		q = "language:Go " + q
	}
	return q
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type ChatResponseChoice struct {
	Message ChatMessage `json:"message"`
}

type ChatResponse struct {
	Choices []ChatResponseChoice `json:"choices"`
}

func decomposeGoal(cfg Config, macroGoal string) []SubTask {
	logger.Logf("Script-LLM", "正在分析 CVE 0-day 挖掘宏观目标: '%s' ...", macroGoal)

	if cfg.LLMAPIKey == "" {
		return defaultSubTasks()
	}

	prompt := fmt.Sprintf(`你是一名资深漏洞挖掘专家与 DevSecOps 智能体架构师。
用户的核心诉求是："%s"。

关键约束与语法要求：
1. 目标是寻找【真实的、易于部署与本地复现的 Go 语言开源应用】（如 Go CMS、博客系统、管理后台、文件存储传输系统）。
2. 严禁生成关于 ERP、CRM、大型 API 网关或复杂微服务框架的搜索子任务！
3. "search_query" 必须遵守 GitHub API 简单检索语法，格式为简单的关键词组合！格式范例：`+"`language:Go cms stars:>15 pushed:>2023-01-01 archived:false`"+`
4. 严禁在 search_query 中使用复杂的 NOT 逻辑、过多的括号嵌套！

请将该目标拆解为 2 到 3 个 GitHub API 搜索子任务。
每个子任务包含字段：
- "subtask_id": 1, 2...
- "title": 简洁的子任务标题
- "search_query": 极简合法的 GitHub 检索语法
- "focus_cve_types": ["Arbitrary-File-Upload", "SQLi", "RCE"]

请仅输出标准的 JSON 数组，不要添加 Markdown 包裹。`, macroGoal)

	reqPayload := ChatRequest{
		Model: cfg.LLMModel,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
	}

	body, _ := json.Marshal(reqPayload)
	reqURL := strings.TrimRight(cfg.LLMBaseURL, "/") + "/chat/completions"
	headers := map[string]string{
		"Authorization": "Bearer " + cfg.LLMAPIKey,
		"Content-Type":  "application/json",
	}

	code, respBytes, err := httpRequest(reqURL, "POST", headers, body, 25)
	if err == nil && code == 200 {
		var chatResp ChatResponse
		if err := json.Unmarshal(respBytes, &chatResp); err == nil && len(chatResp.Choices) > 0 {
			content := strings.TrimSpace(chatResp.Choices[0].Message.Content)
			content = cleanJSON(content)
			var tasks []SubTask
			if err := json.Unmarshal([]byte(content), &tasks); err == nil && len(tasks) > 0 {
				logger.Logf("Script-LLM", "LLM 成功将目标拆解为 %d 个原子化子任务！", len(tasks))
				return tasks
			}
		}
	}

	logger.Logf("Script-LLM", "LLM 接口响应异常，使用备用 0-day 策略队列")
	return defaultSubTasks()
}

func evaluateRepo(cfg Config, item GitHubRepoItem, focusTypes []string) EvaluationResult {
	if cfg.LLMAPIKey == "" {
		return EvaluationResult{
			Score:              75,
			Reason:             "未配置 LLM API Key，使用默认策略入队进行 SAST 静态扫描",
			RecommendedProfile: "zero_day_only",
		}
	}

	prompt := fmt.Sprintf(`你是一名高水平漏洞挖掘专家与 CVE 审核员。请评估以下 Go 开源项目的【新 CVE 申请潜力与 0-day 挖掘价值】。

仓库名称: %s
项目描述: %s
Stars: %d
Topics: %v
主页地址: %s

评估过滤原则：
1. 严格剔除（打 0 分）：如果是故意设计的教学漏洞靶场 (如 vulnerable-app, testbed, ctf) 或已知历史 CVE 漏洞记录集合，严禁入选！
2. 评估高潜力（打高分）：如果是真实的、生产可用的 Go 业务应用/系统，存在参数解析、文件上传或命令执行等，具备挖掘未公开 0-day 价值的。

请以 JSON 格式输出评估结果：
1. "score": 整数(0-100)，代表申请新 CVE 的潜力分。低于 50 分将被自动过滤。
2. "reason": 一句话中文总结评估理由。
3. "recommended_profile": 扫描策略 ("zero_day_only" 或 "baseline")。

仅输出合法 JSON 字符串。`, item.FullName, item.Description, item.StargazersCount, item.Topics, item.HTMLURL)

	reqPayload := ChatRequest{
		Model: cfg.LLMModel,
		Messages: []ChatMessage{
			{Role: "user", Content: prompt},
		},
		Temperature: 0.2,
	}

	body, _ := json.Marshal(reqPayload)
	reqURL := strings.TrimRight(cfg.LLMBaseURL, "/") + "/chat/completions"
	headers := map[string]string{
		"Authorization": "Bearer " + cfg.LLMAPIKey,
		"Content-Type":  "application/json",
	}

	code, respBytes, err := httpRequest(reqURL, "POST", headers, body, 20)
	if err == nil && code == 200 {
		var chatResp ChatResponse
		if err := json.Unmarshal(respBytes, &chatResp); err == nil && len(chatResp.Choices) > 0 {
			content := cleanJSON(chatResp.Choices[0].Message.Content)
			var evalRes EvaluationResult
			if err := json.Unmarshal([]byte(content), &evalRes); err == nil {
				return evalRes
			}
		}
	}

	return EvaluationResult{
		Score:              65,
		Reason:             fmt.Sprintf("LLM API 响应 HTTP %d", code),
		RecommendedProfile: "zero_day_only",
	}
}

func cleanJSON(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "```") {
		idx := strings.Index(s, "\n")
		if idx != -1 {
			s = s[idx+1:]
		}
		s = strings.TrimSuffix(s, "```")
	}
	first := strings.Index(s, "{")
	last := strings.LastIndex(s, "}")
	if first != -1 && last > first {
		s = s[first : last+1]
	}
	firstArr := strings.Index(s, "[")
	lastArr := strings.LastIndex(s, "]")
	if firstArr != -1 && lastArr > firstArr && (first == -1 || firstArr < first) {
		s = s[firstArr : lastArr+1]
	}
	return strings.TrimSpace(s)
}

func defaultSubTasks() []SubTask {
	return []SubTask{
		{
			SubTaskID:     1,
			Title:         "检索近期活跃的 Go 语言开源 CMS / 博客内容管理系统",
			SearchQuery:   "language:Go cms stars:>15 pushed:>2023-01-01 archived:false",
			FocusCVETypes: []string{"Arbitrary-File-Upload", "SQLi", "RCE"},
		},
		{
			SubTaskID:     2,
			Title:         "检索轻量级 Go 文件传输与云存储管理服务",
			SearchQuery:   "language:Go file sharing stars:>20 pushed:>2023-01-01 archived:false",
			FocusCVETypes: []string{"Path-Traversal", "Arbitrary-File-Upload", "RCE"},
		},
		{
			SubTaskID:     3,
			Title:         "检索基于 Gin/Fiber 框架构建的简易后台管理系统",
			SearchQuery:   "language:Go admin panel stars:>20 pushed:>2023-01-01 archived:false",
			FocusCVETypes: []string{"RCE", "Auth-Bypass", "SQLi"},
		},
	}
}

func fetchGitHubRepos(query, token string, maxCount int) []GitHubRepoItem {
	cleanQuery := sanitizeGitHubQuery(query)
	reqURL := fmt.Sprintf("https://api.github.com/search/repositories?q=%s&sort=stars&order=desc&per_page=%d",
		url.QueryEscape(cleanQuery), maxCount)

	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "token " + token
	}

	code, data, err := httpRequest(reqURL, "GET", headers, nil, 15)
	if err != nil || code != 200 {
		logger.Logf("Script-GitHub", "[WARN] API 查询失败 [%s]: HTTP %d, err=%v", cleanQuery, code, err)
		return nil
	}

	var resp GitHubSearchResponse
	if err := json.Unmarshal(data, &resp); err == nil {
		return resp.Items
	}
	return nil
}

func fetchExistingRepoURLs(backendURL string) map[string]bool {
	existing := make(map[string]bool)
	reqURL := strings.TrimRight(backendURL, "/") + "/api/v1/repos/list?page=1&per_page=500"
	code, data, err := httpRequest(reqURL, "GET", nil, nil, 10)
	if err != nil || code != 200 {
		return existing
	}

	var resp struct {
		Data struct {
			Data []struct {
				URL  string `json:"url"`
				Name string `json:"name"`
			} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(data, &resp); err == nil {
		for _, item := range resp.Data.Data {
			if item.URL != "" {
				existing[normalizeGitURL(item.URL)] = true
			}
			if item.Name != "" {
				existing[strings.ToLower(item.Name)] = true
			}
		}
	}
	return existing
}

func registerAndQueueScan(backendURL string, repo GitHubRepoItem, evalRes EvaluationResult, querySuite string, useAI bool) (bool, string) {
	base := strings.TrimRight(backendURL, "/")
	regURL := base + "/api/v1/repos"

	branch := repo.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	cloneURL := repo.CloneURL
	if cloneURL == "" {
		cloneURL = repo.HTMLURL + ".git"
	}

	regPayload := map[string]interface{}{
		"name":      repo.Name,
		"url":       cloneURL,
		"language":  "go",
		"branch":    branch,
		"stars":     repo.StargazersCount,
		"auth_type": "none",
	}

	regBody, _ := json.Marshal(regPayload)
	code, respBytes, err := httpRequest(regURL, "POST", map[string]string{"Content-Type": "application/json"}, regBody, 10)
	if err != nil || (code != 200 && code != 201) {
		return false, fmt.Sprintf("注册仓库失败 HTTP %d: %s", code, string(respBytes))
	}

	var regResp struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(respBytes, &regResp)
	repoID := regResp.Data.ID
	if repoID == 0 {
		return false, "注册仓库成功但未返回有效 repo_id"
	}

	scanURL := base + "/api/v1/scan/tasks"
	scanPayload := map[string]interface{}{
		"repo_id":              repoID,
		"language":             "go",
		"branch":               branch,
		"rule_profile":         evalRes.RecommendedProfile,
		"use_ai_verification": useAI,
	}
	if querySuite != "" {
		scanPayload["query_suite"] = querySuite
	}

	scanBody, _ := json.Marshal(scanPayload)
	codeScan, scanRespBytes, errScan := httpRequest(scanURL, "POST", map[string]string{"Content-Type": "application/json"}, scanBody, 10)
	if errScan == nil && (codeScan == 200 || codeScan == 201) {
		return true, fmt.Sprintf("提交成功 (RepoID=%d)", repoID)
	}
	return false, fmt.Sprintf("注册成功 (ID=%d)，但入队失败 HTTP %d: %s", repoID, codeScan, string(scanRespBytes))
}

func main() {
	configPath := flag.String("config", "scripts/config.json", "配置文件路径")
	dryRun := flag.Bool("dry-run", false, "仅搜索与评估，不实际入队")
	goal := flag.String("goal", "", "自定义 0-day 搜集目标说明")
	querySuite := flag.String("query-suite", "", "指定使用的 CodeQL 规则套件 (.ql / .qls)")
	disableAI := flag.Bool("disable-ai", false, "关闭 LLM 漏洞验证复现功能")
	flag.Parse()

	cfg := loadConfig(*configPath)
	if *goal != "" {
		cfg.MacroGoal = *goal
	}

	suite := *querySuite
	if suite == "" {
		suite = cfg.QuerySuite
	}

	useAI := !*disableAI
	if *disableAI {
		useAI = false
	} else if !cfg.UseAIVerification {
		useAI = false
	}

	logger.Logf("Script-Collector", "==================================================")
	logger.Logf("Script-Collector", "Go 开源仓库潜在漏洞目标搜集与入队 (Go 原生版本)")
	logger.Logf("Script-Collector", "后端地址: %s", cfg.BackendURL)
	logger.Logf("Script-Collector", "LLM 模型: %s (API Key: %s)", cfg.LLMModel, ternary(cfg.LLMAPIKey != "", "已配置", "未配置"))
	logger.Logf("Script-Collector", "CodeQL 规则套件: %s", ternary(suite != "", suite, "默认策略库"))
	logger.Logf("Script-Collector", "AI 语义验证: %s", ternary(useAI, "开启", "关闭"))
	logger.Logf("Script-Collector", "==================================================")

	subtasks := decomposeGoal(cfg, cfg.MacroGoal)
	logger.Logf("Script-Collector", "加载已存在仓库进行查重集合构建...")
	existingMap := fetchExistingRepoURLs(cfg.BackendURL)
	logger.Logf("Script-Collector", "数据库中已存在 %d 条查重匹配项", len(existingMap))

	var logs []string
	queuedCount := 0
	skippedCount := 0

	for idx, st := range subtasks {
		logger.Logf("Script-Collector", "[任务 %d/%d] %s (Query: %s)", idx+1, len(subtasks), st.Title, st.SearchQuery)

		items := fetchGitHubRepos(st.SearchQuery, cfg.GitHubToken, cfg.MaxReposPerQuery)
		for _, repo := range items {
			cleanURL := normalizeGitURL(repo.CloneURL)
			if cleanURL == "" {
				cleanURL = normalizeGitURL(repo.HTMLURL)
			}
			repoName := strings.ToLower(repo.Name)

			if existingMap[cleanURL] || existingMap[repoName] {
				logger.Logf("Script-Collector", "  [Skip Existing] %s", repo.FullName)
				skippedCount++
				continue
			}

			evalRes := evaluateRepo(cfg, repo, st.FocusCVETypes)
			logger.Logf("Script-Collector", "  [Target] %s | Stars: %d | 得分: %d | 原因: %s",
				repo.FullName, repo.StargazersCount, evalRes.Score, evalRes.Reason)

			if evalRes.Score < 50 {
				logger.Logf("Script-Collector", "  [Skip Low Score] %s", repo.FullName)
				skippedCount++
				continue
			}

			if *dryRun {
				logger.Logf("Script-Collector", "  [Dry Run] 跳过入队 %s", repo.FullName)
				continue
			}

			ok, msg := registerAndQueueScan(cfg.BackendURL, repo, evalRes, suite, useAI)
			if ok {
				logger.Logf("Script-Collector", "  [Queued] %s -> %s", repo.FullName, msg)
				queuedCount++
				existingMap[cleanURL] = true
				logs = append(logs, fmt.Sprintf("QUEUED: %s -> %s", repo.FullName, msg))
			} else {
				logger.Logf("Script-Collector", "  [Failed] %s -> %s", repo.FullName, msg)
				logs = append(logs, fmt.Sprintf("FAILED: %s -> %s", repo.FullName, msg))
			}
		}
	}

	_ = os.MkdirAll("./result", 0755)
	summaryPath := filepath.Join("./result", "discovery_summary.log")
	summaryContent := fmt.Sprintf("Zero-Day Discovery Summary Log - %s\nQueued: %d, Skipped: %d\n\n%s\n",
		time.Now().Format("2006-01-02 15:04:05"), queuedCount, skippedCount, strings.Join(logs, "\n"))
	_ = os.WriteFile(summaryPath, []byte(summaryContent), 0644)

	logger.Logf("Script-Collector", "搜集总结报告已保存至: %s", summaryPath)
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}
