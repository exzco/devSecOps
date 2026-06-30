#!/usr/bin/env bash
# DevSecOps Platform — 扫描引擎二进制依赖检测与安装脚本
#
# 检测项: nmap (端口扫描/服务指纹) · nuclei (PoC 扫描)
# 流程: 检测已安装 → 已有则退出 → 未有则识别系统 → 执行安装

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}   $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

# ── 系统识别 ──────────────────────────────────────────────────────────────────
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"; return
    fi
    if [[ ! -f /etc/os-release ]]; then
        echo "unknown"; return
    fi
    local id
    id=$(awk -F= '/^ID=/{gsub(/"/, "", $2); print tolower($2)}' /etc/os-release)
    case "$id" in
        ubuntu|debian|linuxmint) echo "debian" ;;
        centos|rhel|rocky|almalinux) echo "rhel" ;;
        fedora) echo "fedora" ;;
        arch|manjaro) echo "arch" ;;
        *) echo "unknown" ;;
    esac
}

# ── 安装函数 ──────────────────────────────────────────────────────────────────
install_nmap() {
    local os="$1"
    echo "  → 安装 nmap..."
    case "$os" in
        debian) sudo apt-get update -qq && sudo apt-get install -y nmap ;;
        rhel)   sudo yum install -y nmap 2>/dev/null || sudo dnf install -y nmap ;;
        fedora) sudo dnf install -y nmap ;;
        arch)   sudo pacman -Sy --noconfirm nmap ;;
        macos)  brew install nmap ;;
        *)
            fail "nmap: 未识别的系统 ($os)，请手动安装: https://nmap.org/download"
            return 1
            ;;
    esac
}

install_nuclei() {
    local os="$1"
    echo "  → 安装 nuclei..."
    case "$os" in
        macos)
            brew install nuclei
            ;;
        debian|rhel|fedora|arch)
            # 通过官方 install 脚本安装最新版（写入 /usr/local/bin）
            curl -fsSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip \
                -o /tmp/nuclei.zip
            unzip -qo /tmp/nuclei.zip nuclei -d /tmp/
            sudo mv /tmp/nuclei /usr/local/bin/nuclei
            sudo chmod +x /usr/local/bin/nuclei
            rm -f /tmp/nuclei.zip
            ;;
        *)
            fail "nuclei: 未识别的系统 ($os)，请手动安装: https://github.com/projectdiscovery/nuclei/releases"
            return 1
            ;;
    esac
}

install_fingerprintx() {
    local os="$1"
    echo "  → 安装 fingerprintx..."
    case "$os" in
        macos)
            if command -v go &>/dev/null; then
                go install github.com/projectdiscovery/fingerprintx/cmd/fingerprintx@latest
            else
                curl -fsSL https://github.com/projectdiscovery/fingerprintx/releases/latest/download/fingerprintx_darwin_amd64.zip -o /tmp/fingerprintx.zip
                unzip -qo /tmp/fingerprintx.zip fingerprintx -d /tmp/
                sudo mv /tmp/fingerprintx /usr/local/bin/fingerprintx
                sudo chmod +x /usr/local/bin/fingerprintx
                rm -f /tmp/fingerprintx.zip
            fi
            ;;
        debian|rhel|fedora|arch)
            curl -fsSL https://github.com/projectdiscovery/fingerprintx/releases/latest/download/fingerprintx_linux_amd64.zip -o /tmp/fingerprintx.zip
            unzip -qo /tmp/fingerprintx.zip fingerprintx -d /tmp/
            sudo mv /tmp/fingerprintx /usr/local/bin/fingerprintx
            sudo chmod +x /usr/local/bin/fingerprintx
            rm -f /tmp/fingerprintx.zip
            ;;
        *)
            fail "fingerprintx: 未识别的系统 ($os)，请手动安装: https://github.com/projectdiscovery/fingerprintx"
            return 1
            ;;
    esac
}

# ── 单项检测流程 ──────────────────────────────────────────────────────────────
# 返回值: 0=已有/安装成功  1=安装失败
check_and_install() {
    local name="$1"
    local os="$2"

    if command -v "$name" &>/dev/null; then
        local ver; ver=$("$name" --version 2>&1 | head -1)
        ok "$name  已安装  ($ver)"
        return 0
    fi

    warn "$name  未找到，开始安装..."
    if "install_${name}" "$os"; then
        if command -v "$name" &>/dev/null; then
            local ver; ver=$("$name" --version 2>&1 | head -1)
            ok "$name  安装成功  ($ver)"
            return 0
        fi
    fi

    fail "$name  安装失败"
    return 1
}

# ── 主流程 ────────────────────────────────────────────────────────────────────
main() {
    echo ""
    echo -e " DevSecOps Platform — 扫描引擎依赖检测"
    echo ""

    local os; os=$(detect_os)
    echo "  系统: $os"
    echo ""

    local failed=0
    check_and_install nmap          "$os" || ((failed++)) || true
    check_and_install nuclei        "$os" || ((failed++)) || true
    check_and_install fingerprintx  "$os" || ((failed++)) || true

    echo ""
    if [[ $failed -eq 0 ]]; then
        ok "所有依赖就绪"
    else
        fail "$failed 个依赖安装失败，请手动处理后重试"
        exit 1
    fi
}

main "$@"
