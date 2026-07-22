// Package preflight 在 DevSecOps 平台启动前检测并通过 curl 零依赖自动下载安装缺失的二进制工具链。
package preflight

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type CheckResult struct {
	Name     string
	Found    bool
	Version  string
	Required bool
}

// DependTool 结构体用于声明依赖工具配置
type DependTool struct {
	Name        string
	Required    bool
	VersionArgs []string
}

// RunChecks 执行系统全局依赖工具链检测。
// 移除特定操作系统的包管理器依赖，统一采用 curl 方式直接从发行版地址拉取并安装可执行二进制文件。
func RunChecks(autoInstall bool, failFast bool) []CheckResult {
	log.Println("[preflight] 开始 DevSecOps 平台启动前依赖检测...")
	initNucleiEnv()
	// 2. 定义平台核心依赖工具清单 (软提醒模式：不阻断平台启动)
	tools := []DependTool{
		{Name: "git", Required: false, VersionArgs: []string{"--version"}},
		{Name: "semgrep", Required: false, VersionArgs: []string{"--version"}},
		{Name: "nuclei", Required: false, VersionArgs: []string{"-version"}},
		{Name: "nmap", Required: false, VersionArgs: []string{"--version"}},
		{Name: "fingerprintx", Required: false, VersionArgs: []string{"--version"}},
	}

	var checks []CheckResult
	missingCount := 0

	for _, tool := range tools {
		res := checkBinary(tool.Name, tool.Required, tool.VersionArgs, autoInstall)
		checks = append(checks, res)

		if res.Found {
			log.Printf("[preflight] ✔ %-12s %s", res.Name, res.Version)
		} else {
			log.Printf("[preflight] ○ %-12s 未找到 (可选依赖工具)", res.Name)
			missingCount++
		}
	}

	if missingCount > 0 {
		log.Printf("[preflight] 提示: 检测到 %d 个依赖工具未找到，相关依赖功能被触发时可能受限。", missingCount)
	}

	return checks
}

// checkBinary 检测单个二进制文件是否存在，支持 curl 自动尝试安装
func checkBinary(name string, required bool, versionArgs []string, autoInstall bool) CheckResult {
	res := CheckResult{Name: name, Required: required}

	if path, err := exec.LookPath(name); err == nil && path != "" {
		res.Found = true
		res.Version = binaryVersion(name, versionArgs...)
		return res
	}

	if autoInstall {
		log.Printf("[preflight] %s 未找到，尝试通过 curl 自动下载安装...", name)
		if err := tryInstallViaCurl(name); err == nil {
			if _, errLook := exec.LookPath(name); errLook == nil {
				res.Found = true
				res.Version = binaryVersion(name, versionArgs...)
				log.Printf("[preflight] %s 通过 curl 自动安装成功", name)
				return res
			}
		} else {
			log.Printf("[preflight] %s curl 自动安装失败: %v", name, err)
		}
	}

	return res
}

// initNucleiEnv 静默创建 Nuclei 配置文件结构
func initNucleiEnv() {
	if home, err := os.UserHomeDir(); err == nil {
		ignoreDir := filepath.Join(home, ".config", "nuclei")
		_ = os.MkdirAll(ignoreDir, 0755)
		ignoreFile := filepath.Join(ignoreDir, ".nuclei-ignore")
		if _, err := os.Stat(ignoreFile); os.IsNotExist(err) {
			_ = os.WriteFile(ignoreFile, []byte(""), 0644)
		}
	}
}

// tryInstallViaCurl 使用 curl 从官方/GitHub Releases 下载最新二进制文件并安装至系统 PATH
func tryInstallViaCurl(name string) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return fmt.Errorf("curl 自动下载目前仅支持 Linux / macOS 系统，当前系统: %s", runtime.GOOS)
	}

	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("暂不支持的架构: %s", arch)
	}

	switch name {
	case "nuclei":
		url := fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_%s_%s.zip", runtime.GOOS, arch)
		return downloadZipAndInstall(url, "nuclei")

	case "fingerprintx":
		url := fmt.Sprintf("https://github.com/projectdiscovery/fingerprintx/releases/latest/download/fingerprintx_%s_%s.zip", runtime.GOOS, arch)
		return downloadZipAndInstall(url, "fingerprintx")

	case "semgrep":
		// 使用官方一键脚本进行无包管理器安装
		return runCmd("sh", "-c", "curl -fsSL https://semgrep.dev/get.sh | sh")

	default:
		return fmt.Errorf("工具 %s 需系统核心动态库（如 nmap/git），请直接运行二进制脚本或系统包进行安装", name)
	}
}

// downloadZipAndInstall 通用 curl 下载 ZIP 解压并移动至 /usr/local/bin 的方法
func downloadZipAndInstall(url string, binName string) error {
	tmpZip := fmt.Sprintf("/tmp/%s.zip", binName)

	log.Printf("[preflight] 正在通过 curl 下载 %s: %s", binName, url)
	if err := runCmd("curl", "-fsSL", url, "-o", tmpZip); err != nil {
		return fmt.Errorf("curl 下载 %s 失败: %w", binName, err)
	}
	defer os.Remove(tmpZip)

	log.Printf("[preflight] 解压并安装 %s 到 /usr/local/bin/", binName)
	if err := runCmd("unzip", "-qo", tmpZip, binName, "-d", "/tmp/"); err != nil {
		return fmt.Errorf("解压 %s 失败: %w", binName, err)
	}
	defer os.Remove(fmt.Sprintf("/tmp/%s", binName))

	// 移动并赋予可执行权限
	if err := runCmd("sudo", "mv", fmt.Sprintf("/tmp/%s", binName), fmt.Sprintf("/usr/local/bin/%s", binName)); err != nil {
		// 回退方案：如果不带 sudo 直接尝试写入 /usr/local/bin
		if errFallback := runCmd("mv", fmt.Sprintf("/tmp/%s", binName), fmt.Sprintf("/usr/local/bin/%s", binName)); errFallback != nil {
			return fmt.Errorf("安装二进制文件至 /usr/local/bin 失败: %w", err)
		}
	}

	_ = runCmd("sudo", "chmod", "+x", fmt.Sprintf("/usr/local/bin/%s", binName))
	return nil
}

func binaryVersion(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "未知版本"
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if len(lines) > 0 {
		return lines[0]
	}
	return ""
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("[preflight] 执行: %s %s", name, strings.Join(args, " "))
	return cmd.Run()
}
