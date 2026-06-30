// Package preflight 在服务启动前检测并（可选）自动安装所需的宿主机二进制依赖。
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

// RunChecks 执行所有启动前依赖检测，autoInstall=true 时尝试自动安装缺失项。
// 返回缺失且必需的依赖数量；若 > 0 且 failFast=true，则直接退出进程。
func RunChecks(autoInstall bool, failFast bool) []CheckResult {
	log.Println("[preflight] 开始启动前依赖检测...")

	// 自动初始化 nuclei 规避配置文件，防止 nuclei SDK 报错刷屏
	if home, err := os.UserHomeDir(); err == nil {
		ignoreDir := filepath.Join(home, ".config", "nuclei")
		_ = os.MkdirAll(ignoreDir, 0755)
		ignoreFile := filepath.Join(ignoreDir, ".nuclei-ignore")
		if _, err := os.Stat(ignoreFile); os.IsNotExist(err) {
			_ = os.WriteFile(ignoreFile, []byte(""), 0644)
		}
	}

	checks := []CheckResult{
		checkNmap(autoInstall),
		checkFingerprintx(autoInstall),
	}

	missing := 0
	for _, r := range checks {
		if r.Found {
			log.Printf("[preflight] ✔ %-10s %s", r.Name, r.Version)
		} else if r.Required {
			log.Printf("[preflight] ✘ %-10s 未找到 (必需)", r.Name)
			missing++
		} else {
			log.Printf("[preflight] ○ %-10s 未找到 (可选)", r.Name)
		}
	}

	if missing > 0 && failFast {
		log.Fatalf("[preflight] %d 个必需依赖缺失，服务无法启动。请运行 scripts/detect_and_install_deps.sh 安装后重试", missing)
	}

	return checks
}

// ─────────────────────────────────────────────────────────────────────────────
// nmap 检测与自动安装
// ─────────────────────────────────────────────────────────────────────────────

func checkNmap(autoInstall bool) CheckResult {
	r := CheckResult{Name: "nmap", Required: true}

	if _, err := exec.LookPath("nmap"); err == nil {
		r.Found = true
		r.Version = binaryVersion("nmap", "--version")
		return r
	}

	if !autoInstall {
		return r
	}

	log.Println("[preflight] nmap 未找到，尝试自动安装...")
	if installErr := installNmap(); installErr != nil {
		log.Printf("[preflight] nmap 自动安装失败: %v", installErr)
		log.Println("[preflight] 请手动安装 nmap：")
		log.Println("[preflight]   Debian/Ubuntu : sudo apt-get install -y nmap")
		log.Println("[preflight]   CentOS/RHEL   : sudo yum install -y nmap")
		log.Println("[preflight]   Fedora        : sudo dnf install -y nmap")
		log.Println("[preflight]   macOS         : brew install nmap")
		return r
	}

	// 安装后再检测一次
	if _, err := exec.LookPath("nmap"); err == nil {
		r.Found = true
		r.Version = binaryVersion("nmap", "--version")
		log.Println("[preflight] nmap 安装成功")
	}
	return r
}

// installNmap 根据操作系统执行对应的包管理器安装命令
func installNmap() error {
	switch runtime.GOOS {
	case "linux":
		return installNmapLinux()
	case "darwin":
		return installNmapMacOS()
	default:
		return fmt.Errorf("不支持的操作系统: %s，请手动安装 nmap", runtime.GOOS)
	}
}

func installNmapLinux() error {
	distro := detectLinuxDistro()
	log.Printf("[preflight] Linux 发行版: %s", distro)

	switch distro {
	case "debian":
		// 先 update，再 install（静默模式）
		if err := runCmd("sudo", "apt-get", "update", "-qq"); err != nil {
			return fmt.Errorf("apt-get update 失败: %w", err)
		}
		return runCmd("sudo", "apt-get", "install", "-y", "-qq", "nmap")

	case "rhel":
		// 先尝试 yum，再 fallback 到 dnf
		if err := runCmd("sudo", "yum", "install", "-y", "nmap"); err != nil {
			return runCmd("sudo", "dnf", "install", "-y", "nmap")
		}
		return nil

	case "fedora":
		return runCmd("sudo", "dnf", "install", "-y", "nmap")

	case "arch":
		return runCmd("sudo", "pacman", "-Sy", "--noconfirm", "nmap")

	default:
		// 未知发行版：逐一尝试常见包管理器
		for _, args := range [][]string{
			{"sudo", "apt-get", "install", "-y", "nmap"},
			{"sudo", "yum", "install", "-y", "nmap"},
			{"sudo", "dnf", "install", "-y", "nmap"},
		} {
			if err := runCmd(args[0], args[1:]...); err == nil {
				return nil
			}
		}
		return fmt.Errorf("无法识别的发行版，所有包管理器安装均失败")
	}
}

func installNmapMacOS() error {
	// 检查 Homebrew
	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("未找到 Homebrew，请先安装 Homebrew 再运行：brew install nmap")
	}
	return runCmd("brew", "install", "nmap")
}

// ─────────────────────────────────────────────────────────────────────────────
// 工具函数
// ─────────────────────────────────────────────────────────────────────────────

// detectLinuxDistro 读取 /etc/os-release 判断发行版
func detectLinuxDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}
	content := string(data)
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "ID=") {
			id := strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), "\"' "))
			switch id {
			case "ubuntu", "debian", "linuxmint", "pop":
				return "debian"
			case "centos", "rhel", "rocky", "almalinux":
				return "rhel"
			case "fedora":
				return "fedora"
			case "arch", "manjaro", "endeavouros":
				return "arch"
			}
		}
	}
	return "unknown"
}

// binaryVersion 获取二进制版本字符串的第一行
func binaryVersion(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	return lines[0]
}

// runCmd 执行命令，将 stdout/stderr 输出到日志
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	log.Printf("[preflight] 执行: %s %s", name, strings.Join(args, " "))
	return cmd.Run()
}

// ─────────────────────────────────────────────────────────────────────────────
// fingerprintx 检测与自动安装 (退化探测兜底)
// ─────────────────────────────────────────────────────────────────────────────

func checkFingerprintx(autoInstall bool) CheckResult {
	r := CheckResult{Name: "fingerprintx", Required: false}

	if _, err := exec.LookPath("fingerprintx"); err == nil {
		r.Found = true
		r.Version = binaryVersion("fingerprintx", "--version")
		return r
	}

	if !autoInstall {
		return r
	}

	log.Println("[preflight] fingerprintx 未找到，尝试自动安装...")
	if installErr := installFingerprintx(); installErr != nil {
		log.Printf("[preflight] fingerprintx 自动安装失败: %v，请手动安装", installErr)
		return r
	}

	if _, err := exec.LookPath("fingerprintx"); err == nil {
		r.Found = true
		r.Version = binaryVersion("fingerprintx", "--version")
		log.Println("[preflight] fingerprintx 自动安装成功")
	}
	return r
}

func installFingerprintx() error {
	switch runtime.GOOS {
	case "linux":
		return installFingerprintxLinux()
	default:
		return fmt.Errorf("不支持的操作系统自动安装: %s，请手动安装 fingerprintx", runtime.GOOS)
	}
}

func installFingerprintxLinux() error {
	zipURL := "https://github.com/projectdiscovery/fingerprintx/releases/latest/download/fingerprintx_linux_amd64.zip"
	tmpZip := "/tmp/fingerprintx.zip"

	if err := runCmd("curl", "-fsSL", zipURL, "-o", tmpZip); err != nil {
		return fmt.Errorf("下载 fingerprintx 失败: %w", err)
	}
	defer os.Remove(tmpZip)

	if err := runCmd("unzip", "-qo", tmpZip, "fingerprintx", "-d", "/tmp/"); err != nil {
		return fmt.Errorf("解压 fingerprintx 失败: %w", err)
	}

	if err := runCmd("sudo", "mv", "/tmp/fingerprintx", "/usr/local/bin/fingerprintx"); err != nil {
		return fmt.Errorf("安装二进制文件失败: %w", err)
	}

	return runCmd("sudo", "chmod", "+x", "/usr/local/bin/fingerprintx")
}
