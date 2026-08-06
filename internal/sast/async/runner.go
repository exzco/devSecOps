package async

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hibiken/asynq"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"devsecops/internal/config"
	"devsecops/internal/sast/agent"
	"devsecops/pkg/logger"
	"devsecops/internal/sast/model"
	"devsecops/internal/sast/scanner"
)

var (
	activeTasksMu sync.Mutex
	activeTasks   = make(map[uint]context.CancelFunc)
)

func CancelTask(taskID uint) {
	activeTasksMu.Lock()
	defer activeTasksMu.Unlock()

	if cancel, exists := activeTasks[taskID]; exists {
		cancel()
	}
}

type TaskRunner struct {
	db     *gorm.DB
	worker *scanner.ScanWorker
	openAI config.OpenAIConfig
}

func NewTaskRunner(db *gorm.DB, worker *scanner.ScanWorker, openAI config.OpenAIConfig) *TaskRunner {
	return &TaskRunner{db: db, worker: worker, openAI: openAI}
}

func (r *TaskRunner) ProcessTask(ctx context.Context, t *asynq.Task) error {
	switch t.Type() {
	case TypeScanRepo:
		return r.handleScanRepo(ctx, t)
	default:
		return fmt.Errorf("unknown task type: %s", t.Type())
	}
}

func (r *TaskRunner) handleScanRepo(ctx context.Context, t *asynq.Task) error {
	var payload ScanRepoPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("deserialize task payload: %w", err)
	}

	logger.SAST("Runner", "start scan repo_id=%d task_id=%d", payload.RepoID, payload.TaskID)

	var task model.ScanTask
	if err := r.db.First(&task, payload.TaskID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.SAST("Runner", "task missing, skip task_id=%d", payload.TaskID)
			return nil
		}
		return fmt.Errorf("load task %d: %w", payload.TaskID, err)
	}

	var repo model.Repository
	if err := r.db.First(&repo, payload.RepoID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			r.appendTaskLog(payload.TaskID, "repository not found, task canceled")
			r.db.Model(&task).Updates(map[string]interface{}{
				"status":    model.TaskStatusCanceled,
				"error_msg": "repository not found",
			})
			return nil
		}
		return fmt.Errorf("load repo %d: %w", payload.RepoID, err)
	}

	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	activeTasksMu.Lock()
	activeTasks[payload.TaskID] = cancel
	activeTasksMu.Unlock()

	defer func() {
		activeTasksMu.Lock()
		delete(activeTasks, payload.TaskID)
		activeTasksMu.Unlock()
	}()

	now := time.Now()
	r.db.Model(&task).Updates(map[string]interface{}{
		"status":        model.TaskStatusRunning,
		"started_at":    now,
		"execution_log": fmt.Sprintf("[%s] task started\n", now.Format("2006-01-02 15:04:05")),
	})
	r.appendTaskLog(payload.TaskID, fmt.Sprintf("scan started repo=%s branch=%s language=%s", repo.Name, task.Branch, repo.Language))

	vulns, sarifPath, err := r.worker.RunScan(taskCtx, &task, &repo, repo.AuthSecret, func(message string) {
		r.appendTaskLog(payload.TaskID, message)
	})
	finished := time.Now()
	duration := finished.Sub(now).Milliseconds()

	if err != nil {
		if errors.Is(taskCtx.Err(), context.Canceled) {
			if ctx.Err() != nil {
				logger.SAST("Runner", "task %d interrupted by worker shutdown: %v", payload.TaskID, ctx.Err())
				return fmt.Errorf("worker interrupted: %w", err)
			}
			logger.SAST("Runner", "task %d canceled", payload.TaskID)
			return nil
		}
		r.appendTaskLog(payload.TaskID, "scan failed: "+err.Error())
		r.db.Model(&task).Updates(map[string]interface{}{
			"status":      model.TaskStatusFailed,
			"finished_at": finished,
			"duration_ms": duration,
			"error_msg":   err.Error(),
		})
		return fmt.Errorf("run scan: %w", err)
	}

	r.saveResults(payload.RepoID, payload.TaskID, repo.URL, vulns)
	r.appendTaskLog(payload.TaskID, fmt.Sprintf("saved %d vulnerabilities", len(vulns)))

	r.db.Model(&task).Updates(map[string]interface{}{
		"status":      model.TaskStatusSuccess,
		"finished_at": finished,
		"duration_ms": duration,
		"sarif_path":  sarifPath,
		"vuln_count":  len(vulns),
	})
	r.appendTaskLog(payload.TaskID, fmt.Sprintf("task completed in %dms", duration))

	if task.UseAIVerification {
		r.appendTaskLog(payload.TaskID, "starting AI verification in background...")
		go r.triggerAIAudit(payload.TaskID, task.Language, repo.URL, "project source: "+repo.URL)
	}

	logger.SAST("Runner", "task %d completed in %dms", payload.TaskID, duration)
	return nil
}

func (r *TaskRunner) appendTaskLog(taskID uint, message string) {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return
	}
	line := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), trimmed)
	r.db.Model(&model.ScanTask{}).
		Where("id = ?", taskID).
		Update("execution_log", gorm.Expr("COALESCE(execution_log, '') || ?", line))
}

func (r *TaskRunner) saveResults(repoID, taskID uint, repoURL string, results []scanner.ParsedVulnerability) {
	for _, p := range results {
		dataFlowJSON, _ := json.Marshal(p.DataFlow)

		vuln := &model.Vulnerability{
			ScanTaskID:  taskID,
			RepoID:      repoID,
			Fingerprint: p.Fingerprint,
		}

		r.db.Where("repo_id = ? AND fingerprint = ?", repoID, p.Fingerprint).
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

func (r *TaskRunner) triggerAIAudit(taskID uint, language, repoURL, projectDesc string) {
	var vulns []model.Vulnerability
	if err := r.db.Where("scan_task_id = ?", taskID).Find(&vulns).Error; err != nil {
		logger.SAST("AI-Audit", "failed to fetch vulnerabilities for task %d: %v", taskID, err)
		return
	}

	apiKey := os.Getenv("DEEPSEEK_API_KEY")
	baseURL := ""

	modelName := ""
	if r.openAI.APIKey != "" {
		apiKey = r.openAI.APIKey
		baseURL = r.openAI.BaseURL
		modelName = r.openAI.Model
	}

	if apiKey == "" {
		logger.SAST("AI-Audit", "DEEPSEEK_API_KEY not set, skip task %d", taskID)
		r.appendTaskLog(taskID, "skip AI verification: missing api key")
		return
	}

	r.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] start semantic analysis for %d vulnerabilities", len(vulns)))

	auditor := agent.NewAppSecAuditor(agent.AuditorConfig{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Model:   modelName,
	})
	ctx := context.Background()

	logFn := func(msg string) {
		logger.SAST("AI-Audit", "%s", msg)
		r.appendTaskLog(taskID, msg)
	}

	successCount := 0
	for _, vuln := range vulns {
		if isLowImpactRule(vuln.RuleID) {
			r.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] skip low-impact rule %s", vuln.RuleID))
			skipResult := map[string]interface{}{
				"is_false_positive":      true,
				"confidence":             "High",
				"vulnerability_analysis": fmt.Sprintf("rule %s is auto-filtered as low-impact", vuln.RuleID),
				"remediation_suggestion": "prefer structured logging such as slog or zap",
				"manual_poc":             "not required",
			}
			resultJSON, _ := json.Marshal(skipResult)
			r.db.Model(&vuln).Updates(map[string]interface{}{
				"ai_result": datatypes.JSON(resultJSON),
				"status":    model.VulnStatusFalsePositive,
			})
			successCount++
			continue
		}

		codeCtx := fmt.Sprintf("Rule: %s\nFile: %s:%d\nSnippet:\n%s", vuln.RuleID, vuln.FilePath, vuln.StartLine, vuln.CodeSnippet)

		result, err := auditor.AnalyzeVulnerability(ctx, vuln.RuleName, language, projectDesc, codeCtx, logFn)
		if err != nil {
			logger.SAST("AI-Audit", "failed for vuln %d: %v", vuln.ID, err)
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

		r.db.Model(&vuln).Updates(updates)
		successCount++
	}

	r.appendTaskLog(taskID, fmt.Sprintf("[AI-Audit] completed %d/%d vulnerabilities", successCount, len(vulns)))
}

func isLowImpactRule(ruleID string) bool {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	lowKeywords := []string{
		"log-injection",
		"clear-text-logging",
		"disabled-tls",
		"weak-sensitive-data-hashing",
	}
	for _, kw := range lowKeywords {
		if strings.Contains(ruleID, kw) {
			return true
		}
	}
	return false
}
