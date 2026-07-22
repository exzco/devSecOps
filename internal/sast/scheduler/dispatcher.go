package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/agent"
	"devsecops/internal/config"
	"devsecops/internal/sast/model"
	"devsecops/internal/sast/scanner"
)

var (
	ActiveTasksMu sync.Mutex
	ActiveTasks   = make(map[uint]context.CancelFunc)
)

type TaskDispatcher struct {
	db     *gorm.DB
	worker *scanner.ScanWorker
}

func NewTaskDispatcher(db *gorm.DB, worker *scanner.ScanWorker) *TaskDispatcher {
	return &TaskDispatcher{db: db, worker: worker}
}

func (d *TaskDispatcher) ProcessTask(ctx context.Context, t *asynq.Task) error {
	switch t.Type() {
	case TypeScanRepo:
		return d.handleScanRepo(ctx, t)
	default:
		return fmt.Errorf("未知任务类型: %s", t.Type())
	}
}

func (d *TaskDispatcher) handleScanRepo(ctx context.Context, t *asynq.Task) error {
	var payload ScanRepoPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("反序列化载荷失败: %w", err)
	}

	log.Printf("[Asynq] 开始处理扫描任务: repo_id=%d, task_id=%d", payload.RepoID, payload.TaskID)

	var task model.ScanTask
	if err := d.db.First(&task, payload.TaskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Printf("[Asynq] 扫描任务不存在，跳过处理: task_id=%d", payload.TaskID)
			return nil
		}
		return fmt.Errorf("找不到任务 %d: %w", payload.TaskID, err)
	}

	if task.TriggerType == model.TriggerTypeCron {
		d.appendTaskLog(payload.TaskID, "定时扫描功能已停用，任务自动取消。")
		d.db.Model(&task).Updates(map[string]interface{}{
			"status":    model.TaskStatusCanceled,
			"error_msg": "定时扫描功能已停用",
		})
		return nil
	}

	var repo model.Repository
	if err := d.db.First(&repo, payload.RepoID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			d.appendTaskLog(payload.TaskID, "仓库已删除或不可用，任务自动取消。")
			d.db.Model(&task).Updates(map[string]interface{}{
				"status":    model.TaskStatusCanceled,
				"error_msg": "仓库不存在或已删除",
			})
			return nil
		}
		return fmt.Errorf("找不到仓库 %d: %w", payload.RepoID, err)
	}

	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	ActiveTasksMu.Lock()
	ActiveTasks[payload.TaskID] = cancel
	ActiveTasksMu.Unlock()

	defer func() {
		ActiveTasksMu.Lock()
		delete(ActiveTasks, payload.TaskID)
		ActiveTasksMu.Unlock()
	}()

	now := time.Now()
	d.db.Model(&task).Updates(map[string]interface{}{
		"status":        model.TaskStatusRunning,
		"started_at":    now,
		"execution_log": fmt.Sprintf("[%s] 任务已开始执行\n", now.Format("2006-01-02 15:04:05")),
	})
	d.appendTaskLog(payload.TaskID, fmt.Sprintf("任务入队成功，开始处理。仓库：%s，分支：%s，语言：%s", repo.Name, task.Branch, repo.Language))

	vulns, sarifPath, err := d.worker.RunScan(taskCtx, &task, &repo, repo.AuthSecret, func(message string) {
		d.appendTaskLog(payload.TaskID, message)
	})
	finished := time.Now()
	duration := finished.Sub(now).Milliseconds()

	if err != nil {
		if errors.Is(taskCtx.Err(), context.Canceled) {
			if ctx.Err() != nil {
				log.Printf("[Asynq] 任务 %d 被系统或队列服务中止: %v", payload.TaskID, ctx.Err())
				return fmt.Errorf("系统中断: %w", err)
			}
			log.Printf("[Asynq] 任务 %d 被用户手动取消 (已从任务列表删除)", payload.TaskID)
			return nil
		}
		d.appendTaskLog(payload.TaskID, "扫描任务失败: "+err.Error())
		d.db.Model(&task).Updates(map[string]interface{}{
			"status":      model.TaskStatusFailed,
			"finished_at": finished,
			"duration_ms": duration,
			"error_msg":   err.Error(),
		})
		return fmt.Errorf("扫描失败: %w", err)
	}

	d.saveResults(payload.RepoID, payload.TaskID, repo.URL, vulns)
	d.appendTaskLog(payload.TaskID, fmt.Sprintf("漏洞结果入库完成，共 %d 条", len(vulns)))

	d.db.Model(&task).Updates(map[string]interface{}{
		"status":      model.TaskStatusSuccess,
		"finished_at": finished,
		"duration_ms": duration,
		"sarif_path":  sarifPath,
		"vuln_count":  len(vulns),
	})
	d.appendTaskLog(payload.TaskID, fmt.Sprintf("任务执行成功，耗时 %dms", duration))

	if task.UseAIVerification {
		d.appendTaskLog(payload.TaskID, "配置了 AI 语义分析，即将触发 LLM 误报研判与修复建议生成 (后台执行)...")
		go d.triggerAIAudit(payload.TaskID, task.Language, repo.URL, "项目来源: " + repo.URL)
	}

	log.Printf("[Asynq] 任务 %d 完成，耗时 %dms", payload.TaskID, duration)
	return nil
}

func (d *TaskDispatcher) appendTaskLog(taskID uint, message string) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), trimmed)
	d.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Update("execution_log", gorm.Expr("COALESCE(execution_log, '') || ?", line))
}

func (d *TaskDispatcher) saveResults(repoID, taskID uint, repoURL string, results []scanner.ParsedVulnerability) {
	for _, p := range results {
		dataFlowJSON, _ := json.Marshal(p.DataFlow)

		vuln := &model.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			Fingerprint: p.Fingerprint,
		}

		d.db.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
			Assign(map[string]interface{}{
				"scan_task_id": taskID,
				"repo_url":     repoURL,
				"file_path":    p.FilePath,
				"start_line":   p.StartLine,
				"end_line":     p.EndLine,
				"message":      p.Message,
				"severity":     p.Severity,
				"rule_id":      p.RuleID,
				"rule_name":    p.RuleName,
				"code_snippet": p.CodeSnippet,
				"fingerprint":  p.Fingerprint,
				"data_flow":    datatypes.JSON(dataFlowJSON),
				"status":       model.VulnStatusNew,
			}).
			FirstOrCreate(vuln)
	}
}

func (d *TaskDispatcher) triggerAIAudit(taskID uint, language, repoURL, projectDesc string) {
	var vulns []model.Vulnerability
	if err := d.db.Where("scan_task_id = ?", taskID).Find(&vulns).Error; err != nil {
		log.Printf("[AI-Audit] Failed to fetch vulnerabilities for task %d: %v", taskID, err)
		return
	}

	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	baseURL := ""
	modelName := ""
	if config.GlobalConfig != nil && config.GlobalConfig.OpenAI.APIKey != "" {
		apiKey = config.GlobalConfig.OpenAI.APIKey
		baseURL = config.GlobalConfig.OpenAI.BaseURL
		modelName = config.GlobalConfig.OpenAI.Model
	}

	if apiKey == "" {
		log.Printf("[AI-Audit] DEEPSEEK_API_KEY not set, skipping AI semantic analysis for task %d", taskID)
		d.appendTaskLog(taskID, "跳过 AI 分析：未配置 DEEPSEEK_API_KEY 环境变量或配置文件 api_key")
		return
	}

	d.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] 开始触发 LLM 语义研判与误报分析，共分析 %d 条漏洞...", len(vulns)))

	auditor := agent.NewAppSecAuditor(agent.AuditorConfig{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Model:   modelName,
	})
	ctx := context.Background()

	logFn := func(msg string) {
		log.Println(msg)
		d.appendTaskLog(taskID, msg)
	}

	successCount := 0
	for _, vuln := range vulns {
		if isLowImpactRule(vuln.RuleID) {
			d.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] 规则 %s 属于低危害/日志规范瑕疵，自动跳过 AI API 验证以节省 Token", vuln.RuleID))
			skipResult := map[string]interface{}{
				"is_false_positive":      true,
				"confidence":             "High",
				"vulnerability_analysis": fmt.Sprintf("规则 %s 属于低危害/日志规范瑕疵，已被系统自动归类过滤，无需消耗 AI Token。", vuln.RuleID),
				"remediation_suggestion": "建议使用结构化日志 (如 slog 或 zap) 避免拼接日志。",
				"manual_poc":             "无需复现",
			}
			resultJSON, _ := json.Marshal(skipResult)
			d.db.Model(&vuln).Updates(map[string]interface{}{
				"ai_result": datatypes.JSON(resultJSON),
				"status":    model.VulnStatusFalsePositive,
			})
			successCount++
			continue
		}

		codeCtx := fmt.Sprintf("Rule: %s\nFile: %s:%d\nSnippet:\n%s", vuln.RuleID, vuln.FilePath, vuln.StartLine, vuln.CodeSnippet)
		
		result, err := auditor.AnalyzeVulnerabilityWithLogger(ctx, vuln.RuleName, language, projectDesc, codeCtx, logFn)
		if err != nil {
			log.Printf("[AI-Audit] Failed for vuln %d: %v", vuln.ID, err)
			continue
		}

		resultJSON, _ := json.Marshal(result)
		updates := map[string]interface{}{
			"ai_result": datatypes.JSON(resultJSON),
			"status":    model.VulnStatusAITriaged,
		}
		if result.IsFalsePositive {
			updates["status"] = model.VulnStatusFalsePositive
		}

		d.db.Model(&vuln).Updates(updates)
		successCount++
	}

	d.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] LLM 语义分析阶段完成，共处理 %d 个漏洞，成功分析 %d 个", len(vulns), successCount))
}

func isLowImpactRule(ruleID string) bool {
	r := strings.ToLower(strings.TrimSpace(ruleID))
	lowKeywords := []string{
		"log-injection",
		"clear-text-logging",
		"disabled-tls",
		"weak-sensitive-data-hashing",
	}
	for _, kw := range lowKeywords {
		if strings.Contains(r, kw) {
			return true
		}
	}
	return false
}
