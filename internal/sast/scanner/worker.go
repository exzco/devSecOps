package scanner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"devsecops/internal/config"
	"devsecops/internal/sast/model"
)

type ScanWorker struct {
	git    *GitManager
	codeql *CodeQLRunner
}

type ScanProgressLogger func(message string)

func NewScanWorker(cfg *config.ScannerConfig) *ScanWorker {
	return &ScanWorker{
		git:    NewGitManager(cfg.WorkDir),
		codeql: NewCodeQLRunner(cfg),
	}
}

func (w *ScanWorker) RunScan(ctx context.Context, task *model.ScanTask, repo *model.Repository, authSecret string, progress ScanProgressLogger) ([]ParsedVulnerability, string, error) {
	if progress == nil {
		progress = func(string) {}
	}

	taskID := fmt.Sprintf("%d", task.ID)
	defer func() {
		if err := w.codeql.CleanupGeneratedInputs(taskID); err != nil {
			log.Printf("[Task %d] 清理源码/数据库失败: %v", task.ID, err)
			progress("清理源码/数据库失败: " + err.Error())
		} else {
			progress("清理源码/数据库完成")
		}
	}()

	// 1. git Clone 代码
	log.Printf("[Task %d] 正在拉取代码...", task.ID)
	progress("开始拉取仓库代码")
	srcDir, err := w.git.CloneRepo(ctx, repo.URL, task.Branch, taskID, repo.AuthType, authSecret)
	if err != nil {
		progress("拉取仓库代码失败: " + err.Error())
		return nil, "", err
	}
	progress("仓库代码拉取完成")

	// 2. 创建数据库
	log.Printf("[Task %d] 正在创建 CodeQL 数据库...", task.ID)
	progress("开始创建 CodeQL 数据库")
	dbDir, err := w.codeql.CreateDatabase(ctx, taskID, srcDir, repo.Language, "")
	if err != nil {
		progress("创建 CodeQL 数据库失败: " + err.Error())
		return nil, "", err
	}
	progress("CodeQL 数据库创建完成")

	// 3. 执行分析
	log.Printf("[Task %d] 正在运行 codeql 查询分析...", task.ID)
	progress("开始执行 CodeQL 查询")
	sarifFile, err := w.codeql.Analyze(ctx, taskID, dbDir, repo.Language, task.QuerySuite, task.RuleProfile, task.Rules)
	if err != nil {
		progress("CodeQL 查询执行失败: " + err.Error())
		return nil, "", err
	}
	progress("CodeQL 查询执行完成")

	// 4. 解析 SARIF
	progress("开始解析 SARIF 结果")
	vulns, err := ParseSARIF(sarifFile)
	if err != nil {
		progress("SARIF 解析失败: " + err.Error())
		return nil, "", err
	}
	progress(fmt.Sprintf("SARIF 解析完成，识别到 %d 条漏洞", len(vulns)))

	// 读取源码并补充代码片段
	for i := range vulns {
		// 1. 主漏洞代码片段
		start := vulns[i].StartLine - 15
		if start < 1 {
			start = 1
		}
		end := vulns[i].EndLine + 15
		vulns[i].CodeSnippet = readCodeFromFile(srcDir, vulns[i].FilePath, start, end)

		// 2. 污点追踪链路步骤代码片段
		for j := range vulns[i].DataFlow {
			for k := range vulns[i].DataFlow[j] {
				stepStart := vulns[i].DataFlow[j][k].StartLine - 15
				if stepStart < 1 {
					stepStart = 1
				}
				stepEnd := vulns[i].DataFlow[j][k].EndLine + 15
				vulns[i].DataFlow[j][k].Snippet = readCodeFromFile(srcDir, vulns[i].DataFlow[j][k].FilePath, stepStart, stepEnd)
			}
		}
	}

	return vulns, sarifFile, err
}

func readCodeFromFile(srcDir, filePath string, startLine, endLine int) string {
	if filePath == "" {
		return ""
	}
	absPath := filePath
	if !filepath.IsAbs(filePath) {
		filePath = strings.TrimPrefix(filePath, "/")
		absPath = filepath.Join(srcDir, filePath)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return ""
	}

	total := len(lines)
	if total == 0 {
		return ""
	}

	s := startLine
	if s < 1 {
		s = 1
	}
	e := endLine
	if e > total {
		e = total
	}
	if s > e {
		return ""
	}

	var snippetLines []string
	for i := s - 1; i < e; i++ {
		snippetLines = append(snippetLines, lines[i])
	}
	return strings.Join(snippetLines, "\n")
}
