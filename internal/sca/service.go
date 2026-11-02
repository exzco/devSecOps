package sca

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"devsecops/internal/config"
	"devsecops/internal/model"
	"devsecops/internal/sca/client"
	"devsecops/internal/sca/parser"
)

type ScaService struct {
	db        *gorm.DB
	osvClient *client.OSVClient
	workDir   string
}

func NewScaService(db *gorm.DB, scannerCfg *config.ScannerConfig) *ScaService {
	workDir := "./data/sca_work"
	if scannerCfg != nil && scannerCfg.WorkDir != "" {
		workDir = filepath.Join(scannerCfg.WorkDir, "sca")
	}
	_ = os.MkdirAll(workDir, 0755)

	return &ScaService{
		db:        db,
		osvClient: client.NewOSVClient(),
		workDir:   workDir,
	}
}

// CreateTask creates a new SCA task and triggers background execution
func (s *ScaService) CreateTask(repoID uint, branch, language, targetDir string) (*model.ScaScanTask, error) {
	if strings.TrimSpace(branch) == "" {
		branch = "main"
	}
	if strings.TrimSpace(language) == "" {
		language = "auto"
	}

	task := &model.ScaScanTask{
		RepoID:    repoID,
		TargetDir: targetDir,
		Branch:    branch,
		Language:  language,
	}
	task.Status = model.TaskStatusPending
	task.ExecutionLog = "Task created, waiting for execution\n"

	if err := s.db.Create(task).Error; err != nil {
		return nil, fmt.Errorf("failed to create sca task: %w", err)
	}

	// Trigger asynchronous execution
	go s.runScanAsync(task.ID)

	return task, nil
}

func (s *ScaService) GetTask(id uint) (*model.ScaScanTask, error) {
	var task model.ScaScanTask
	if err := s.db.First(&task, id).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *ScaService) ListTasks(page, pageSize int) ([]model.ScaScanTask, int64, error) {
	var tasks []model.ScaScanTask
	var total int64
	s.db.Model(&model.ScaScanTask{}).Count(&total)

	offset := (page - 1) * pageSize
	if offset < 0 {
		offset = 0
	}
	err := s.db.Order("id desc").Offset(offset).Limit(pageSize).Find(&tasks).Error
	return tasks, total, err
}

func (s *ScaService) GetTaskDependencies(taskID uint) ([]model.ScaDependency, error) {
	var deps []model.ScaDependency
	err := s.db.Where("task_id = ?", taskID).Order("id asc").Find(&deps).Error
	return deps, err
}

func (s *ScaService) GetTaskVulnerabilities(taskID uint) ([]model.ScaVulnerability, error) {
	var vulns []model.ScaVulnerability
	err := s.db.Where("task_id = ?", taskID).Order("id asc").Find(&vulns).Error
	return vulns, err
}

func (s *ScaService) CountSeverities(taskID uint) (map[string]int, error) {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	type result struct {
		Severity string
		Count    int
	}
	var results []result
	err := s.db.Model(&model.ScaVulnerability{}).
		Select("severity, count(*) as count").
		Where("task_id = ?", taskID).
		Group("severity").
		Scan(&results).Error
	if err != nil {
		return nil, err
	}

	for _, r := range results {
		key := strings.ToLower(strings.TrimSpace(r.Severity))
		counts[key] = r.Count
	}

	return counts, nil
}

func (s *ScaService) runScanAsync(taskID uint) {
	startTime := time.Now()
	_ = s.updateStatus(taskID, model.TaskStatusRunning, map[string]any{
		"started_at": &startTime,
	})

	var logBuf strings.Builder
	appendLog := func(msg string) {
		line := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), msg)
		logBuf.WriteString(line)
		_ = s.db.Model(&model.ScaScanTask{}).Where("id = ?", taskID).Update("execution_log", logBuf.String()).Error
	}

	appendLog("Starting SCA analysis")

	var task model.ScaScanTask
	if err := s.db.First(&task, taskID).Error; err != nil {
		return
	}

	scanDir := task.TargetDir
	var cleanupDir string

	if scanDir == "" || !dirExists(scanDir) {
		if task.RepoID == 0 {
			appendLog("Error: neither valid target directory nor repo_id provided")
			s.finishFailed(taskID, "neither valid target directory nor repo_id provided", logBuf.String(), startTime)
			return
		}

		var repo model.Repository
		if err := s.db.First(&repo, task.RepoID).Error; err != nil {
			appendLog(fmt.Sprintf("Error: repository %d not found: %v", task.RepoID, err))
			s.finishFailed(taskID, "repository not found", logBuf.String(), startTime)
			return
		}

		appendLog(fmt.Sprintf("Cloning repository %s (%s)", repo.Name, repo.URL))
		destDir := filepath.Join(s.workDir, fmt.Sprintf("task_%d", taskID), "src")
		_ = os.RemoveAll(destDir)
		_ = os.MkdirAll(destDir, 0755)
		cleanupDir = filepath.Join(s.workDir, fmt.Sprintf("task_%d", taskID))

		cloneURL := repo.URL
		if repo.AuthType == "token" && repo.AuthSecret != "" {
			cloneURL = strings.Replace(cloneURL, "https://", "https://oauth2:"+repo.AuthSecret+"@", 1)
			cloneURL = strings.Replace(cloneURL, "http://", "http://oauth2:"+repo.AuthSecret+"@", 1)
		}

		branch := task.Branch
		if branch == "" {
			branch = repo.Branch
		}
		if branch == "" {
			branch = "main"
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--single-branch", "--branch", branch, cloneURL, destDir)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		out, err := cmd.CombinedOutput()
		cancel()

		if err != nil {
			appendLog(fmt.Sprintf("Git clone failed: %v: %s", err, string(out)))
			s.finishFailed(taskID, fmt.Sprintf("git clone failed: %v", err), logBuf.String(), startTime)
			return
		}

		scanDir = destDir
		appendLog("Repository successfully cloned")
	}

	defer func() {
		if cleanupDir != "" {
			_ = os.RemoveAll(cleanupDir)
		}
	}()

	// Parse dependencies
	appendLog(fmt.Sprintf("Analyzing dependencies in %s (language mode: %s)", scanDir, task.Language))
	var parsedDeps []parser.ParsedDependency
	var err error

	if task.Language != "" && task.Language != "auto" {
		parsedDeps, err = parser.ParseByLanguage(scanDir, task.Language)
	} else {
		parsedDeps, err = parser.DetectAndParse(scanDir)
	}

	if err != nil {
		appendLog(fmt.Sprintf("Dependency detection warning: %v", err))
	}

	appendLog(fmt.Sprintf("Extracted %d unique dependencies across manifests", len(parsedDeps)))

	// Insert dependencies into DB
	depMap := make(map[string]uint) // key -> ID
	for _, pd := range parsedDeps {
		dep := model.ScaDependency{
			TaskID:    taskID,
			RepoID:    task.RepoID,
			Name:      pd.Name,
			Version:   pd.Version,
			Ecosystem: pd.Ecosystem,
			Direct:    pd.Direct,
			License:   pd.License,
			FilePath:  pd.FilePath,
		}
		if err := s.db.Create(&dep).Error; err == nil {
			key := fmt.Sprintf("%s:%s:%s", pd.Ecosystem, pd.Name, pd.Version)
			depMap[key] = dep.ID
		}
	}

	// Match vulnerabilities with OSV
	appendLog("Querying Google OSV vulnerability database...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	findings, matchErr := s.osvClient.CheckDependencies(ctx, parsedDeps)
	cancel()

	if matchErr != nil {
		appendLog(fmt.Sprintf("OSV query warning: %v", matchErr))
	}

	appendLog(fmt.Sprintf("Identified %d potential vulnerabilities", len(findings)))

	var critCount, highCount, medCount, lowCount, infoCount int

	for _, f := range findings {
		depKey := fmt.Sprintf("%s:%s:%s", f.Dependency.Ecosystem, f.Dependency.Name, f.Dependency.Version)
		depID := depMap[depKey]

		switch strings.ToUpper(f.Severity) {
		case model.SeverityCritical:
			critCount++
		case model.SeverityHigh:
			highCount++
		case model.SeverityMedium:
			medCount++
		case model.SeverityLow:
			lowCount++
		default:
			infoCount++
		}

		vuln := model.ScaVulnerability{
			BaseVulnerability: model.BaseVulnerability{
				Severity: f.Severity,
				Title:    f.Title,
			},
			TaskID:         taskID,
			RepoID:         task.RepoID,
			DependencyID:   depID,
			DependencyName: f.Dependency.Name,
			CurrentVersion: f.Dependency.Version,
			Ecosystem:      f.Dependency.Ecosystem,
			VulnID:         f.VulnID,
			Aliases:        f.Aliases,
			Summary:        f.Summary,
			Details:        f.Details,
			FixedVersion:   f.FixedVersion,
			References:     f.ReferencesJSON,
		}
		_ = s.db.Create(&vuln).Error

		// Update dependency vuln count
		if depID > 0 {
			_ = s.db.Model(&model.ScaDependency{}).Where("id = ?", depID).
				UpdateColumn("vuln_count", gorm.Expr("vuln_count + ?", 1)).Error
		}
	}

	finishTime := time.Now()
	durationMs := finishTime.Sub(startTime).Milliseconds()

	appendLog(fmt.Sprintf("SCA analysis finished in %d ms (Critical: %d, High: %d, Medium: %d, Low: %d)",
		durationMs, critCount, highCount, medCount, lowCount))

	_ = s.db.Model(&model.ScaScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":         model.TaskStatusSuccess,
		"total_deps":     len(parsedDeps),
		"vuln_count":     len(findings),
		"critical_count": critCount,
		"high_count":     highCount,
		"medium_count":   medCount,
		"low_count":      lowCount,
		"info_count":     infoCount,
		"execution_log":  logBuf.String(),
		"finished_at":    &finishTime,
		"duration_ms":    durationMs,
	}).Error

	log.Printf("[SCA] Task %d completed: %d deps, %d vulns", taskID, len(parsedDeps), len(findings))
}

func (s *ScaService) finishFailed(taskID uint, errMsg, execLog string, startTime time.Time) {
	finishTime := time.Now()
	durationMs := finishTime.Sub(startTime).Milliseconds()
	_ = s.db.Model(&model.ScaScanTask{}).Where("id = ?", taskID).Updates(map[string]any{
		"status":        model.TaskStatusFailed,
		"error_message": errMsg,
		"execution_log": execLog,
		"finished_at":   &finishTime,
		"duration_ms":   durationMs,
	}).Error
}

func (s *ScaService) updateStatus(taskID uint, status string, updates map[string]any) error {
	if updates == nil {
		updates = make(map[string]any)
	}
	updates["status"] = status
	return s.db.Model(&model.ScaScanTask{}).Where("id = ?", taskID).Updates(updates).Error
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
