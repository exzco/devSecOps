package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"devsecops/internal/config"
	"devsecops/pkg/logger"
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

		logger.SAST("Git", "克隆 %s 失败 (尝试 %d/%d): %v, 输出: %s", repoURL, attempt, maxRetries, err, errMsg)
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
}

func NewCodeQLRunner(cfg *config.ScannerConfig) *CodeQLRunner {
	return &CodeQLRunner{
		codeqlPath:     cfg.CodeQLPath,
		queriesPath:    cfg.CodeQLQueries,
		workDir:        cfg.WorkDir,
		profiles:       cfg.RuleProfiles,
		defaultProfile: cfg.DefaultProfile,
	}
}

func (c *CodeQLRunner) CreateDatabase(ctx context.Context, taskID, sourceDir, language string, buildCommand string) (string, error) {
	dbDir := filepath.Join(c.workDir, taskID, "db")

	args := []string{
		"database", "create",
		dbDir,
		"--language=" + language,
		"--source-root=" + sourceDir,
		"--threads=0",
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
		logger.SAST("CodeQL", "Generated dynamic query suite for task %s at %s with content:\n%s", taskID, qlsPath, qlsContent)
		targets = []string{qlsPath}
	}

	args := []string{
		"database", "analyze",
		dbDir,
	}
	args = append(args, targets...)
	args = append(args,
		"--format=sarif-latest",
		"--output="+outputFile,
		"--threads=0",
		"--search-path="+c.queriesPath,
		"--sarif-add-snippets",
	)

	cmd := exec.CommandContext(ctx, c.codeqlPath, args...)
	logger.SAST("CodeQL", "%s %v", c.codeqlPath, args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("codeql database analyze failed: %w\noutput: %s", err, string(output))
	}
	logger.SAST("CodeQL", "Task %s CodeQL 分析完成，结果文件: %s", taskID, outputFile)

	return outputFile, nil
}

func (c *CodeQLRunner) generateDynamicQLS(targets []string, rules string) string {
	var sb strings.Builder
	for _, target := range targets {
		absTarget := c.resolveTargetPath(target)
		slashPath := filepath.ToSlash(absTarget)
		if strings.HasSuffix(slashPath, ".qls") {
			sb.WriteString(fmt.Sprintf("- import: \"%s\"\n", slashPath))
		} else if strings.HasSuffix(slashPath, ".ql") {
			sb.WriteString(fmt.Sprintf("- query: \"%s\"\n", slashPath))
		} else {
			sb.WriteString(fmt.Sprintf("- queries: \"%s\"\n", slashPath))
		}
	}

	sb.WriteString("- include:\n")
	sb.WriteString("    tags:\n")
	for _, rule := range strings.Split(rules, ",") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}

		normalized := strings.ToLower(rule)
		normalized = strings.ReplaceAll(normalized, "_", "-")
		if !strings.HasPrefix(normalized, "cwe-") {
			normalized = "cwe-" + strings.TrimPrefix(normalized, "cwe")
		}

		sb.WriteString(fmt.Sprintf("      - \"external/cwe/%s\"\n", normalized))

		parts := strings.Split(normalized, "cwe-")
		if len(parts) == 2 {
			digits := parts[1]
			trimmedDigits := strings.TrimLeft(digits, "0")
			if trimmedDigits != digits && trimmedDigits != "" {
				sb.WriteString(fmt.Sprintf("      - \"external/cwe/cwe-%s\"\n", trimmedDigits))
			}
		}
	}
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
		return filepath.Join(c.queriesPath, target)
	}

	return target
}

func (c *CodeQLRunner) getDefaultQuerySuite(language string) string {
	suiteMap := map[string]string{
		"go":         "go\\ql\\src\\codeql-suites\\go-security-extended.qls",
		"java":       "java\\ql\\src\\codeql-suites\\java-security-extended.qls",
		"javascript": "javascript\\ql\\src\\codeql-suites\\javascript-security-extended.qls",
		"python":     "python\\ql\\src\\codeql-suites\\python-security-extended.qls",
	}
	if suite, ok := suiteMap[language]; ok {
		return suite
	}
	return language + "-security-extended"
}

func (c *CodeQLRunner) Cleanup(taskID string) error {
	taskDir := filepath.Join(c.workDir, taskID)
	return os.RemoveAll(taskDir)
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

func (c *CodeQLRunner) GetWorkDir(taskID string) string {
	return filepath.Join(c.workDir, taskID)
}
