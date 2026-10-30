package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"devsecops/internal/config"
)

// DiagnoseSAST 执行 SAST Worker 宿主机运行环境与关键依赖深度核验
func DiagnoseSAST(cfg *config.ScannerConfig) ([]DependencyStatus, []string) {
	var deps []DependencyStatus
	var missing []string

	// 1. 检查 Git CLI
	gitDep := checkCommand("Git CLI", "git", []string{"--version"}, true)
	deps = append(deps, gitDep)
	if gitDep.Required && !gitDep.Installed {
		missing = append(missing, fmt.Sprintf("Git 未安装: %s", gitDep.Message))
	}

	// 2. 检查 CodeQL 可执行文件与版本
	codeqlDep := checkCodeQL(cfg.CodeQLPath)
	deps = append(deps, codeqlDep)
	if codeqlDep.Required && !codeqlDep.Installed {
		missing = append(missing, fmt.Sprintf("CodeQL 引擎不可用: %s", codeqlDep.Message))
	}

	// 3. 检查 CodeQL 官方标准查询规则库 (qlpacks)
	qlpacksDep := checkDirectory("CodeQL 规则库 (qlpacks)", cfg.CodeQLQueries, true)
	deps = append(deps, qlpacksDep)
	if qlpacksDep.Required && !qlpacksDep.Installed {
		missing = append(missing, fmt.Sprintf("CodeQL 规则库缺失: %s", qlpacksDep.Message))
	}

	// 4. 检查 Java JDK 运行时 (CodeQL 分析 Java 所需)
	javaDep := checkJava()
	deps = append(deps, javaDep)
	if javaDep.Required && !javaDep.Installed {
		missing = append(missing, fmt.Sprintf("Java JDK 运行时缺失: %s", javaDep.Message))
	}

	return deps, missing
}

// DiagnoseDAST 执行 DAST Worker 宿主机运行环境与关键依赖深度核验
func DiagnoseDAST(cfg *config.DastConfig) ([]DependencyStatus, []string) {
	var deps []DependencyStatus
	var missing []string

	// 1. 检查 PoC 规则存储目录
	pocDirDep := checkDirectory("PoC 规则库目录", cfg.PocDir, true)
	deps = append(deps, pocDirDep)
	if pocDirDep.Required && !pocDirDep.Installed {
		missing = append(missing, fmt.Sprintf("PoC 目录不可读: %s", pocDirDep.Message))
	}

	// 2. 检查 PoC 索引文件与有效规则数量
	indexDep := checkPoCIndex(cfg.PocDir)
	deps = append(deps, indexDep)
	if indexDep.Required && !indexDep.Installed {
		missing = append(missing, fmt.Sprintf("PoC 规则索引缺失: %s", indexDep.Message))
	}

	// 3. 检查基础外网/DNS 解析网络环境
	netDep := checkNetwork()
	deps = append(deps, netDep)

	return deps, missing
}

func checkCommand(name, binary string, args []string, required bool) DependencyStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	path, err := exec.LookPath(binary)
	if err != nil {
		return DependencyStatus{
			Name:      name,
			Required:  required,
			Installed: false,
			Path:      binary,
			Message:   fmt.Sprintf("在系统 PATH 中未找到可执行文件 '%s'，请确认是否已安装", binary),
		}
	}

	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))
	if err != nil {
		return DependencyStatus{
			Name:      name,
			Required:  required,
			Installed: false,
			Path:      path,
			Message:   fmt.Sprintf("命令执行失败: %v, 输出: %s", err, outputStr),
		}
	}

	firstLine := strings.Split(outputStr, "\n")[0]
	return DependencyStatus{
		Name:      name,
		Required:  required,
		Installed: true,
		Path:      path,
		Version:   firstLine,
		Message:   "就绪且运行正常",
	}
}

func checkCodeQL(targetPath string) DependencyStatus {
	resolvedPath := targetPath
	if resolvedPath == "" {
		if p, err := exec.LookPath("codeql"); err == nil {
			resolvedPath = p
		} else {
			resolvedPath = "/opt/codeql/codeql"
		}
	}

	info, err := os.Stat(resolvedPath)
	if err != nil {
		return DependencyStatus{
			Name:      "CodeQL CLI 引擎",
			Required:  true,
			Installed: false,
			Path:      resolvedPath,
			Message:   fmt.Sprintf("文件不存在: %s。请下载官方 Linux x64 版本的 CodeQL Bundle 并解压配置", resolvedPath),
		}
	}
	if info.IsDir() {
		return DependencyStatus{
			Name:      "CodeQL CLI 引擎",
			Required:  true,
			Installed: false,
			Path:      resolvedPath,
			Message:   fmt.Sprintf("指定的路径是一个目录而不是可执行二进制: %s", resolvedPath),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, resolvedPath, "version")
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))
	if err != nil {
		return DependencyStatus{
			Name:      "CodeQL CLI 引擎",
			Required:  true,
			Installed: false,
			Path:      resolvedPath,
			Message:   fmt.Sprintf("CodeQL 无法执行 (可能缺少执行权限或架构不兼容): %v, 输出: %s", err, outputStr),
		}
	}

	firstLine := strings.Split(outputStr, "\n")[0]
	return DependencyStatus{
		Name:      "CodeQL CLI 引擎",
		Required:  true,
		Installed: true,
		Path:      resolvedPath,
		Version:   firstLine,
		Message:   "CodeQL 引擎就绪",
	}
}

func checkDirectory(name, dirPath string, required bool) DependencyStatus {
	if dirPath == "" {
		return DependencyStatus{
			Name:      name,
			Required:  required,
			Installed: false,
			Message:   "路径未配置",
		}
	}

	info, err := os.Stat(dirPath)
	if err != nil {
		return DependencyStatus{
			Name:      name,
			Required:  required,
			Installed: false,
			Path:      dirPath,
			Message:   fmt.Sprintf("目录不存在: %s", dirPath),
		}
	}
	if !info.IsDir() {
		return DependencyStatus{
			Name:      name,
			Required:  required,
			Installed: false,
			Path:      dirPath,
			Message:   fmt.Sprintf("指定路径不是一个目录: %s", dirPath),
		}
	}

	entries, _ := os.ReadDir(dirPath)
	return DependencyStatus{
		Name:      name,
		Required:  required,
		Installed: true,
		Path:      dirPath,
		Version:   fmt.Sprintf("包含 %d 个子项", len(entries)),
		Message:   "目录访问正常",
	}
}

func checkJava() DependencyStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	path, err := exec.LookPath("java")
	if err != nil {
		return DependencyStatus{
			Name:      "Java JDK 运行时",
			Required:  true,
			Installed: false,
			Path:      "java",
			Message:   "未检测到 Java 运行时 (CodeQL 分析 Java 项目需要 JDK 11+)",
		}
	}

	cmd := exec.CommandContext(ctx, path, "-version")
	out, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(out))
	if err != nil {
		return DependencyStatus{
			Name:      "Java JDK 运行时",
			Required:  true,
			Installed: false,
			Path:      path,
			Message:   fmt.Sprintf("java -version 执行失败: %v", err),
		}
	}

	firstLine := strings.Split(outputStr, "\n")[0]
	return DependencyStatus{
		Name:      "Java JDK 运行时",
		Required:  true,
		Installed: true,
		Path:      path,
		Version:   firstLine,
		Message:   "Java 环境就绪",
	}
}

func checkPoCIndex(pocDir string) DependencyStatus {
	indexPath := filepath.Join(pocDir, "poc_index.json")
	data, err := os.ReadFile(indexPath)
	if err != nil {
		return DependencyStatus{
			Name:      "PoC 规则索引 (poc_index.json)",
			Required:  true,
			Installed: false,
			Path:      indexPath,
			Message:   fmt.Sprintf("未找到 PoC 规则索引文件: %s", indexPath),
		}
	}

	var rules []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &rules); err != nil {
		return DependencyStatus{
			Name:      "PoC 规则索引 (poc_index.json)",
			Required:  true,
			Installed: false,
			Path:      indexPath,
			Message:   fmt.Sprintf("poc_index.json JSON 格式解析失败: %v", err),
		}
	}

	return DependencyStatus{
		Name:      "PoC 规则索引 (poc_index.json)",
		Required:  true,
		Installed: true,
		Path:      indexPath,
		Version:   fmt.Sprintf("%d 条有效 PoC 规则", len(rules)),
		Message:   fmt.Sprintf("成功加载 %d 条 Neutron 验证规则", len(rules)),
	}
}

func checkNetwork() DependencyStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", "8.8.8.8:53")
	if err != nil {
		return DependencyStatus{
			Name:      "基础网络连通性",
			Required:  false,
			Installed: false,
			Message:   fmt.Sprintf("外部网络连接受限: %v", err),
		}
	}
	_ = conn.Close()

	return DependencyStatus{
		Name:      "基础网络连通性",
		Required:  false,
		Installed: true,
		Message:   "网络路由畅通",
	}
}
