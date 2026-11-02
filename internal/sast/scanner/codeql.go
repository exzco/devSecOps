package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"devsecops/internal/config"
)

type GitManager struct {
	workDir string
}

func NewGitManager(workDir string) *GitManager {
	return &GitManager{workDir: workDir}
}

func (g *GitManager) CloneRepo(ctx context.Context, repoURL, branch, taskID string, authType, authSecret string) (string, error) {
	destDir := filepath.Join(g.workDir, taskID, "src")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}

	cloneURL := repoURL
	if authType == "token" && authSecret != "" {
		cloneURL = strings.Replace(cloneURL, "https://", "https://oauth2:"+authSecret+"@", 1)
		cloneURL = strings.Replace(cloneURL, "http://", "http://oauth2:"+authSecret+"@", 1)
	}

	args := []string{
		"-c", "http.postBuffer=524288000",
		"-c", "http.lowSpeedLimit=1000",
		"-c", "http.lowSpeedTime=60",
		"clone",
		"--depth", "1",
		"--single-branch",
	}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, cloneURL, destDir)

	var output []byte
	var err error
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		// 每次重试前清理目标目录
		_ = os.RemoveAll(destDir)
		_ = os.MkdirAll(destDir, 0755)

		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")

		output, err = cmd.CombinedOutput()
		if err == nil {
			return destDir, nil
		}

		errMsg := string(output)
		if strings.Contains(errMsg, "terminal prompts disabled") ||
			strings.Contains(errMsg, "could not read Username") ||
			strings.Contains(errMsg, "Authentication failed") {
			return "", fmt.Errorf("仓库认证失败：无法访问 %s\n如果是私有仓库，请在仓库配置中将 Auth Type 设为 token 并填入有效的 Personal Access Token\n原始错误: %s", repoURL, errMsg)
		}

		log.Printf("[GitManager] 克隆 %s 失败 (尝试 %d/%d): %v, 输出: %s", repoURL, attempt, maxRetries, err, errMsg)
		time.Sleep(time.Duration(attempt*2) * time.Second)
	}

	return "", fmt.Errorf("git clone failed after %d retries: %w, output: %s", maxRetries, err, string(output))
}

func (g *GitManager) GetLatestCommit(ctx context.Context, repoDir string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "HEAD")
	cmd.Dir = repoDir
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get commit: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

type CodeQLRunner struct {
	codeqlPath     string
	queriesPath    string
	workDir        string
	profiles       map[string]config.ScannerRuleProfile
	defaultProfile string
	ramMB          int
	threads        int
}

func NewCodeQLRunner(cfg *config.ScannerConfig) *CodeQLRunner {
	ram := cfg.RamMB
	if ram <= 0 {
		ram = 4096
	}
	threads := cfg.Threads
	if threads <= 0 {
		threads = 4
	}
	return &CodeQLRunner{
		codeqlPath:     cfg.CodeQLPath,
		queriesPath:    cfg.CodeQLQueries,
		workDir:        cfg.WorkDir,
		profiles:       cfg.RuleProfiles,
		defaultProfile: cfg.DefaultProfile,
		ramMB:          ram,
		threads:        threads,
	}
}

func (c *CodeQLRunner) CreateDatabase(ctx context.Context, taskID, sourceDir, language string, buildCommand string) (string, error) {
	dbDir := filepath.Join(c.workDir, taskID, "db")

	ram := c.ramMB
	if ram <= 0 {
		ram = 4096
	}
	threads := c.threads
	if threads <= 0 {
		threads = 4
	}

	args := []string{
		"database", "create",
		dbDir,
		"--language=" + language,
		"--source-root=" + sourceDir,
		fmt.Sprintf("--threads=%d", threads),
		fmt.Sprintf("--ram=%d", ram),
		"--overwrite",
	}

	if buildCommand != "" {
		args = append(args, "--command="+buildCommand)
	}

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database create failed: %w\noutput: %s", err, string(output))
	}

	return dbDir, nil
}

func (c *CodeQLRunner) Analyze(ctx context.Context, taskID, dbDir, language, querySuite, ruleProfile, rules string) (string, error) {
	outputFile := filepath.Join(c.workDir, taskID, "results.sarif")
	targets := c.resolveAnalyzeTargets(language, querySuite, ruleProfile)
	if len(targets) == 0 {
		targets = []string{c.getDefaultQuerySuite(language)}
	}

	if rules != "" {
		qlsContent := c.generateDynamicQLS(targets, rules)
		qlsPath := filepath.Join(c.workDir, taskID, "rules.qls")

		if err := os.MkdirAll(filepath.Dir(qlsPath), 0755); err != nil {
			return "", fmt.Errorf("failed to create directory for dynamic qls: %w", err)
		}
		if err := os.WriteFile(qlsPath, []byte(qlsContent), 0644); err != nil {
			return "", fmt.Errorf("failed to write dynamic qls: %w", err)
		}
		log.Printf("[CodeQL] Generated dynamic query suite for task %s at %s with content:\n%s", taskID, qlsPath, qlsContent)
		targets = []string{qlsPath}
	}

	ram := c.ramMB
	if ram <= 0 {
		ram = 4096
	}
	threads := c.threads
	if threads <= 0 {
		threads = 4
	}

	args := []string{
		"database", "analyze",
		dbDir,
	}
	args = append(args, targets...)
	args = append(args,
		"--format=sarif-latest",
		"--output="+outputFile,
		fmt.Sprintf("--threads=%d", threads),
		fmt.Sprintf("--ram=%d", ram),
		"--search-path="+c.queriesPath,
		"--sarif-add-snippets",
	)

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	log.Printf("[CodeQL] %s %v", c.codeqlPath, args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database analyze failed: %w\noutput: %s", err, string(output))
	}
	log.Printf("[Task %s] CodeQL 分析完成，结果文件: %s", taskID, outputFile)

	return outputFile, nil
}

func findQueriesDir(targetPath string) string {
	dir := targetPath
	if fi, err := os.Stat(targetPath); err != nil || !fi.IsDir() {
		dir = filepath.Dir(targetPath)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "qlpack.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "." || parent == "/" {
			break
		}
		dir = parent
	}
	parent := filepath.Dir(targetPath)
	if strings.EqualFold(filepath.Base(parent), "codeql-suites") {
		return filepath.Dir(parent)
	}
	return parent
}

func (c *CodeQLRunner) generateDynamicQLS(targets []string, rules string) string {
	var sb strings.Builder
	seenSources := make(map[string]struct{})

	for _, target := range targets {
		absTarget := c.resolveTargetPath(target)
		slashPath := filepath.ToSlash(absTarget)
		var sourceLine string
		if strings.HasSuffix(slashPath, ".qls") {
			queriesDir := filepath.ToSlash(findQueriesDir(absTarget))
			sourceLine = fmt.Sprintf("- queries: \"%s\"\n", queriesDir)
		} else if strings.HasSuffix(slashPath, ".ql") {
			sourceLine = fmt.Sprintf("- query: \"%s\"\n", slashPath)
		} else {
			queriesDir := filepath.ToSlash(findQueriesDir(absTarget))
			if _, err := os.Stat(filepath.Join(queriesDir, "qlpack.yml")); err == nil {
				sourceLine = fmt.Sprintf("- queries: \"%s\"\n", queriesDir)
			} else if strings.Contains(target, "/") {
				sourceLine = fmt.Sprintf("- queries: '.'\n  from: \"%s\"\n", target)
			} else {
				sourceLine = fmt.Sprintf("- queries: \"%s\"\n", slashPath)
			}
		}
		if _, exists := seenSources[sourceLine]; !exists {
			seenSources[sourceLine] = struct{}{}
			sb.WriteString(sourceLine)
		}
	}

	var tagRules []string
	var idRules []string

	for _, rule := range strings.Split(rules, ",") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		if strings.Contains(rule, "/") {
			idRules = append(idRules, rule)
			continue
		}

		normalized := strings.ToLower(rule)
		normalized = strings.ReplaceAll(normalized, "_", "-")
		if !strings.HasPrefix(normalized, "cwe-") {
			normalized = "cwe-" + strings.TrimPrefix(normalized, "cwe")
		}

		tagRules = append(tagRules, fmt.Sprintf("external/cwe/%s", normalized))

		parts := strings.Split(normalized, "cwe-")
		if len(parts) == 2 {
			digits := parts[1]
			trimmedDigits := strings.TrimLeft(digits, "0")
			if trimmedDigits != "" {
				tagRules = append(tagRules, fmt.Sprintf("external/cwe/cwe-%s", trimmedDigits))
				if num, err := strconv.Atoi(trimmedDigits); err == nil {
					tagRules = append(tagRules, fmt.Sprintf("external/cwe/cwe-%03d", num))
				}
			}
		}
	}

	seenTags := make(map[string]struct{})
	var uniqueTags []string
	for _, tag := range tagRules {
		if _, ok := seenTags[tag]; !ok {
			seenTags[tag] = struct{}{}
			uniqueTags = append(uniqueTags, tag)
		}
	}

	if len(uniqueTags) > 0 {
		sb.WriteString("- include:\n")
		sb.WriteString("    tags contain:\n")
		for _, tag := range uniqueTags {
			sb.WriteString(fmt.Sprintf("      - \"%s\"\n", tag))
		}
	}

	seenIDs := make(map[string]struct{})
	var uniqueIDs []string
	for _, id := range idRules {
		if _, ok := seenIDs[id]; !ok {
			seenIDs[id] = struct{}{}
			uniqueIDs = append(uniqueIDs, id)
		}
	}

	if len(uniqueIDs) > 0 {
		sb.WriteString("- include:\n")
		sb.WriteString("    id:\n")
		for _, id := range uniqueIDs {
			sb.WriteString(fmt.Sprintf("      - \"%s\"\n", id))
		}
	}

	sb.WriteString("- exclude:\n")
	sb.WriteString("    deprecated: //\n")
	sb.WriteString("- exclude:\n")
	sb.WriteString("    query path:\n")
	sb.WriteString("      - /^experimental\\/.*/\n")

	return sb.String()
}

func (c *CodeQLRunner) resolveAnalyzeTargets(language, querySuite, ruleProfile string) []string {
	seen := make(map[string]struct{})
	targets := make([]string, 0, 8)

	add := func(raw string) {
		t := c.resolveTargetPath(strings.TrimSpace(raw))
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		targets = append(targets, t)
	}

	profileName := strings.TrimSpace(ruleProfile)
	if profileName == "" {
		profileName = strings.TrimSpace(c.defaultProfile)
	}

	if profileName != "" {
		if profile, ok := c.profiles[profileName]; ok {
			if profile.IncludeDefault {
				add(c.getDefaultQuerySuite(language))
			}
			for _, t := range profile.Targets {
				add(t)
			}
		}
	}

	for _, part := range strings.Split(strings.TrimSpace(querySuite), ",") {
		add(part)
	}

	if len(targets) == 0 {
		add(c.getDefaultQuerySuite(language))
	}

	return targets
}

func (c *CodeQLRunner) resolveTargetPath(target string) string {
	if target == "" {
		return ""
	}

	if filepath.IsAbs(target) {
		return target
	}

	if abs, err := filepath.Abs(target); err == nil {
		if _, statErr := os.Stat(abs); statErr == nil {
			return abs
		}
	}

	if strings.HasSuffix(target, ".ql") || strings.HasSuffix(target, ".qls") ||
		strings.Contains(target, "\\") || strings.Contains(target, "/") {
		candidate := filepath.Join(c.queriesPath, target)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// 尝试在 queriesPath 下搜索该套件名 (例如 java-security-extended 或 java-security-extended.qls)
	suiteFile := target
	if !strings.HasSuffix(suiteFile, ".qls") && !strings.HasSuffix(suiteFile, ".ql") {
		suiteFile += ".qls"
	}
	if matches, err := filepath.Glob(filepath.Join(c.queriesPath, "codeql", "*", "*", "codeql-suites", suiteFile)); err == nil && len(matches) > 0 {
		return matches[len(matches)-1]
	}
	if matches, err := filepath.Glob(filepath.Join(c.queriesPath, "*", "ql", "src", "codeql-suites", suiteFile)); err == nil && len(matches) > 0 {
		return matches[len(matches)-1]
	}

	return target
}

func (c *CodeQLRunner) getDefaultQuerySuite(language string) string {
	// 新版 CodeQL (≥2.13) qlpack 目录结构:
	//   qlpacks/codeql/<lang>-queries/<version>/codeql-suites/<lang>-security-extended.qls
	// 旧版 CodeQL (≤2.12) qlpack 目录结构:
	//   qlpacks/<lang>/ql/src/codeql-suites/<lang>-security-extended.qls
	// 此处动态探测，优先使用新版路径，回退到旧版路径，最后回退到裸套件名。
	suiteName := language + "-security-extended.qls"

	// 新版路径: qlpacks/codeql/<lang>-queries/*/codeql-suites/<suite>
	newStyleGlob := filepath.Join(c.queriesPath, "codeql", language+"-queries", "*", "codeql-suites", suiteName)
	if matches, err := filepath.Glob(newStyleGlob); err == nil && len(matches) > 0 {
		return matches[len(matches)-1] // 取版本号最大（字典序最后）的
	}

	// 旧版路径: qlpacks/<lang>/ql/src/codeql-suites/<suite>
	oldStylePath := filepath.Join(c.queriesPath, language, "ql", "src", "codeql-suites", suiteName)
	if _, err := os.Stat(oldStylePath); err == nil {
		return oldStylePath
	}

	// 回退到裸套件名，依赖 CodeQL --search-path 自行解析
	return language + "-security-extended"
}

func (c *CodeQLRunner) CleanupGeneratedInputs(taskID string) error {
	baseDir := filepath.Join(c.workDir, taskID)
	if err := os.RemoveAll(filepath.Join(baseDir, "src")); err != nil {
		return err
	}
	if err := os.RemoveAll(filepath.Join(baseDir, "db")); err != nil {
		return err
	}
	return nil
}
