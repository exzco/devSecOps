#!/usr/bin/env bash
# ==============================================================================
# DevSecOps Platform - OWASP Benchmark 1.2 自动化复现评估执行脚本
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SERVER_URL="${SERVER_URL:-http://localhost:22211}"
GROUND_TRUTH="${SCRIPT_DIR}/expectedresults-1.2.csv"
REPO_URL="${BENCHMARK_REPO_URL:-https://github.com/OWASP-Benchmark/BenchmarkJava.git}"
REPO_BRANCH="${BENCHMARK_BRANCH:-master}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"
TIMEOUT="${TIMEOUT:-7200}"

CLR_CYAN="\033[1;36m"
CLR_GREEN="\033[1;32m"
CLR_YELLOW="\033[1;33m"
CLR_RED="\033[1;31m"
CLR_RESET="\033[0m"

# 1. 检查 Python 3 环境
if ! command -v python3 &>/dev/null; then
  echo -e "${CLR_RED}[!] 未检测到 python3，请先安装 Python 3 环境。${CLR_RESET}"
  exit 1
fi

# 2. 检查真值表
if [ ! -f "${GROUND_TRUTH}" ]; then
  echo -e "${CLR_YELLOW}[*] 本地未发现真值表，正在自动从官方仓库拉取...${CLR_RESET}"
  curl -sSL "https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv" -o "${GROUND_TRUTH}"
fi

# 3. 检查 Server 状态
echo -e "${CLR_CYAN}[*]${CLR_RESET} 正在核验 DevSecOps Server 服务可用性 (${SERVER_URL})..."
if ! curl -sf "${SERVER_URL}/health" >/dev/null 2>&1; then
  echo -e "${CLR_YELLOW}[!]${CLR_RESET} 警告: ${SERVER_URL} 无法连接。"
  echo -e "    • 请确保已启动服务: ./devsecops-server --config configs/example.yaml"
  echo -e "    • 以及 SAST Worker: ./devsecops-worker-sast --config configs/example.yaml"
fi

# 4. 传递全部外部参数并执行主驱动
echo -e "${CLR_GREEN}[✓]${CLR_RESET} 启动端到端全量评测驱动..."
python3 "${SCRIPT_DIR}/eval_benchmark.py" \
  --server "${SERVER_URL}" \
  --ground-truth "${GROUND_TRUTH}" \
  --repo-url "${REPO_URL}" \
  --repo-branch "${REPO_BRANCH}" \
  --poll-interval "${POLL_INTERVAL}" \
  --timeout "${TIMEOUT}" \
  "$@"
