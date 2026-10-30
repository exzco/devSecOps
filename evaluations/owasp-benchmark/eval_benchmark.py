#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DevSecOps Platform - OWASP Benchmark v1.2 End-to-End SAST Evaluation Driver
---------------------------------------------------------------------------
严格遵循终端与 CLI 输出样式规范 (Terminal Output Styling Guide) 与全局质量门禁要求。
支持对运行中的 devsecops-server / worker-sast 进行端到端全链路自动化评测。
包含双套件（开箱 Baseline vs CWE 靶向强化）对比评估、鲁棒容错隔离、高精度计分板与 Markdown 报告导出。
"""

import os
import sys
import json
import time
import re
import argparse
import urllib.request
import urllib.error
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass, field

# ==================== ANSI 终端颜色与样式规范 ====================
CLR_RESET   = "\033[0m"
CLR_CYAN    = "\033[1;36m"   # 大标题边框、主要操作步骤标记 [*]、整体横幅 Banner
CLR_GREEN   = "\033[1;32m"   # 成功状态 [✓]、高优通过指标、正向指标 (TP, TPR/Recall)
CLR_RED     = "\033[1;31m"   # 错误、警示、负向指标 (FP, FN, FPR)
CLR_YELLOW  = "\033[1;33m"   # 核心结论与焦点指标 (OWASP Score, Youden's J)
CLR_BLUE    = "\033[1;34m"   # 次要配置参数、环境标签
CLR_WHITE   = "\033[1;37m"   # 分类/分节子标题 (配合 Emoji)

def print_header(title: str, emoji: str = "🎯"):
    """极简标题呈现，不使用厚重等号横幅"""
    print(f"\n{CLR_CYAN}{emoji} {title}{CLR_RESET}")
    print(f"{CLR_BLUE}{'-' * 81}{CLR_RESET}")

def print_step(msg: str):
    print(f"{CLR_CYAN}[*]{CLR_RESET} {msg}")

def print_success(msg: str):
    print(f"{CLR_GREEN}[✓]{CLR_RESET} {msg}")

def print_warning(msg: str):
    print(f"{CLR_YELLOW}[!]{CLR_RESET} {msg}")

def print_error(msg: str):
    print(f"{CLR_RED}[!] {msg}{CLR_RESET}")

def print_item(key: str, val: Any, indent: int = 4, val_color: str = CLR_WHITE):
    spaces = " " * indent
    print(f"{spaces}• {CLR_WHITE}{key:<26}{CLR_RESET}: {val_color}{val}{CLR_RESET}")


# ==================== OWASP Benchmark 规则与类别映射 ====================
# 11 个官方标准分类与 CWE 映射字典
BENCHMARK_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "cmdi": {
        "name": "Command Injection",
        "cwe": 78,
        "cwes": ["cwe-078", "cwe-78"],
        "rules": ["java/command-line-injection", "cwe-078", "cwe-78"],
    },
    "crypto": {
        "name": "Weak Cryptography",
        "cwe": 327,
        "cwes": ["cwe-327"],
        "rules": ["java/weak-cryptographic-algorithm", "cwe-327"],
    },
    "hash": {
        "name": "Weak Hash Algorithm",
        "cwe": 328,
        "cwes": ["cwe-328"],
        "rules": ["java/weak-cryptographic-hash", "cwe-328"],
    },
    "ldapi": {
        "name": "LDAP Injection",
        "cwe": 90,
        "cwes": ["cwe-090", "cwe-90"],
        "rules": ["java/ldap-injection", "cwe-090", "cwe-90"],
    },
    "pathtraver": {
        "name": "Path Traversal",
        "cwe": 22,
        "cwes": ["cwe-022", "cwe-22"],
        "rules": ["java/path-injection", "cwe-022", "cwe-22"],
    },
    "securecookie": {
        "name": "Insecure Cookie",
        "cwe": 614,
        "cwes": ["cwe-614"],
        "rules": ["java/insecure-cookie", "cwe-614"],
    },
    "sqli": {
        "name": "SQL Injection",
        "cwe": 89,
        "cwes": ["cwe-089", "cwe-89"],
        "rules": ["java/sql-injection", "cwe-089", "cwe-89"],
    },
    "trustbound": {
        "name": "Trust Boundary",
        "cwe": 501,
        "cwes": ["cwe-501"],
        "rules": ["java/trust-boundary-violation", "cwe-501"],
    },
    "weakrand": {
        "name": "Weak Randomness",
        "cwe": 330,
        "cwes": ["cwe-330"],
        "rules": ["java/insecure-randomness", "cwe-330"],
    },
    "xpathi": {
        "name": "XPath Injection",
        "cwe": 643,
        "cwes": ["cwe-643"],
        "rules": ["java/xpath-injection", "cwe-643"],
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "cwe": 79,
        "cwes": ["cwe-079", "cwe-79"],
        "rules": ["java/xss", "cwe-079", "cwe-79"],
    },
}

ALL_BENCHMARK_CWES = [
    "cwe-022", "cwe-078", "cwe-079", "cwe-089", "cwe-090",
    "cwe-327", "cwe-328", "cwe-330", "cwe-501", "cwe-614", "cwe-643"
]


class FatalInfrastructureError(Exception):
    """底层基础设施或关键依赖缺失导致的致命错误（如 CodeQL 未安装、路径错误）"""
    pass

# ==================== 数据结构模型 ====================
@dataclass
class GroundTruth:
    test_name: str       # e.g., BenchmarkTest00001
    category: str        # e.g., pathtraver
    real_vuln: bool      # True or False
    cwe: int             # e.g., 22

@dataclass
class MetricSummary:
    total: int = 0
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    tpr: float = 0.0     # Recall
    fpr: float = 0.0     # False Alarm Rate
    precision: float = 0.0
    f1_score: float = 0.0
    youden_j: float = 0.0
    owasp_score: float = 0.0 # youden_j * 100%


# ==================== HTTP 请求客户端 ====================
class PlatformClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, endpoint: str, data: Optional[Dict[str, Any]] = None, timeout: int = 60) -> Tuple[int, Any]:
        url = f"{self.base_url}{endpoint}"
        req_data = None
        headers = {"Accept": "application/json"}
        if data is not None:
            req_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                body = resp.read().decode("utf-8")
                try:
                    return status, json.loads(body)
                except Exception:
                    return status, body
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8")
            try:
                return e.code, json.loads(err_body)
            except Exception:
                return e.code, err_body
        except Exception as e:
            return 0, str(e)


# ==================== 评估核心引擎 ====================
class BenchmarkEvaluator:
    def __init__(
        self,
        server_url: str,
        ground_truth_path: str,
        repo_url: str,
        repo_branch: str = "master",
        custom_repo_id: Optional[int] = None,
        poll_interval: int = 10,
        max_wait_seconds: int = 7200,
    ):
        self.client = PlatformClient(server_url)
        self.ground_truth_path = ground_truth_path
        self.repo_url = repo_url
        self.repo_branch = repo_branch
        self.custom_repo_id = custom_repo_id
        self.poll_interval = poll_interval
        self.max_wait_seconds = max_wait_seconds

        self.ground_truth: Dict[str, GroundTruth] = {}
        self.repo_id: Optional[int] = None

    def load_ground_truth(self) -> bool:
        """加载 OWASP Benchmark v1.2 预期真值表"""
        if not os.path.exists(self.ground_truth_path):
            print_error(f"真值文件不存在: {self.ground_truth_path}")
            return False

        try:
            with open(self.ground_truth_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 4:
                        test_name = parts[0]
                        category = parts[1].lower()
                        real_vuln = parts[2].lower() == "true"
                        cwe = int(parts[3])
                        self.ground_truth[test_name] = GroundTruth(test_name, category, real_vuln, cwe)

            print_success(f"成功载入标准真值表: 共计 {len(self.ground_truth)} 个测试用例")
            return True
        except Exception as e:
            print_error(f"解析真值文件失败: {e}")
            return False

    def preflight_check(self) -> bool:
        """预检 devsecops-server 服务连通性"""
        print_step("正在检查 DevSecOps 平台联通性...")
        status, res = self.client.request("GET", "/health", timeout=5)
        if status != 200:
            print_error(f"无法连接到 DevSecOps 平台 (URL: {self.client.base_url}, HTTP {status})")
            print_item("错误详情", str(res), indent=4, val_color=CLR_RED)
            print_warning("请确认平台是否已启动: ./devsecops-server --config configs/example.yaml")
            return False

        print_success("平台健康检查通过: devsecops-server 运行正常")
        return True

    def ensure_repository(self) -> bool:
        """确保靶场仓库在平台中已注册"""
        if self.custom_repo_id:
            self.repo_id = self.custom_repo_id
            print_success(f"使用用户指定的目标仓库 RepoID: {self.repo_id}")
            return True

        print_step(f"检查是否已注册目标基准仓库: {self.repo_url}")
        status, res = self.client.request("GET", "/api/v1/repos?page=1&per_page=100")
        if status == 200 and isinstance(res, dict) and "data" in res:
            repos = res["data"].get("data", [])
            for r in repos:
                if r.get("url") == self.repo_url:
                    self.repo_id = r.get("id")
                    print_success(f"已发现已注册的基准仓库: RepoID={self.repo_id}, Name={r.get('name')}")
                    return True

        # 未注册则发起注册
        print_step("未检测到预置基准仓库，正在自动注册仓库...")
        payload = {
            "name": "OWASP-BenchmarkJava-1.2",
            "url": self.repo_url,
            "branch": self.repo_branch,
            "language": "java",
            "auth_type": "none",
            "auth_secret": ""
        }
        status, res = self.client.request("POST", "/api/v1/repos", payload)
        if status in (200, 201) and isinstance(res, dict) and "data" in res:
            self.repo_id = res["data"].get("id")
            print_success(f"基准仓库注册成功: RepoID={self.repo_id}")
            return True

        print_error(f"注册仓库失败: HTTP {status}, 响应: {res}")
        return False

    def submit_and_wait(self, suite_name: str, rule_profile: str, rules: List[str]) -> Optional[int]:
        """提交扫描任务并阻塞等待完成"""
        print_step(f"[{suite_name}] 正在向平台提交 SAST 扫描任务...")
        payload = {
            "type": "sast",
            "repo_id": self.repo_id,
            "branch": self.repo_branch,
            "language": "java",
            "rule_profile": rule_profile,
            "rules": rules
        }
        status, res = self.client.request("POST", "/api/v1/scans", payload)
        if status != 202 or not isinstance(res, dict) or "data" not in res:
            print_error(f"[{suite_name}] 任务提交失败: HTTP {status}, 内容: {res}")
            return None

        scan_info = res["data"]
        scan_id = scan_info.get("scan_id")
        task_id = scan_info.get("task_id")
        print_success(f"[{suite_name}] 扫描任务已进入执行队列: ScanID={scan_id}, TaskID={task_id}")

        # 轮询等待任务完成并实时同步 Worker 执行日志与动态进度
        start_time = time.time()
        last_status = ""
        logged_lines_count = 0
        last_stage = "初始化中"
        has_shown_hint = False

        while True:
            elapsed = int(time.time() - start_time)
            if elapsed > self.max_wait_seconds:
                print_error(f"[{suite_name}] 等待任务超时 (超过 {self.max_wait_seconds} 秒)")
                return None

            # 1. 检查任务主状态
            s_status, s_res = self.client.request("GET", f"/api/v1/scans/{scan_id}")
            if s_status == 200 and isinstance(s_res, dict) and "data" in s_res:
                cur_data = s_res["data"]
                cur_status = cur_data.get("status", "unknown")
                is_finished = cur_data.get("finished", False)

                if cur_status != last_status:
                    print_step(f"[{suite_name}] 任务状态变更: {CLR_BLUE}{cur_status.upper()}{CLR_RESET} (已耗时 {elapsed}s)")
                    last_status = cur_status
                    if cur_status == "running" and not has_shown_hint:
                        has_shown_hint = True
                        print_step(f"[{suite_name}] 提示: BenchmarkJava 包含 2,740 个用例，首次建库需自动调用 Maven 编译并提取 AST (通常需 3~8 分钟)，随后执行深度污点分析 (需 5~15 分钟)，后台全力执行中...")

                # 2. 实时拉取 Worker 回传的任务执行进度日志
                if task_id:
                    l_status, l_res = self.client.request("GET", f"/api/v1/scan/tasks/{task_id}/logs")
                    if l_status == 200 and isinstance(l_res, dict) and "data" in l_res:
                        logs = l_res["data"].get("logs", [])
                        if len(logs) > logged_lines_count:
                            for line in logs[logged_lines_count:]:
                                print_step(f"[{suite_name}] 进度更新: {CLR_WHITE}{line}{CLR_RESET}")
                            logged_lines_count = len(logs)
                            if logs:
                                last_stage = logs[-1]
                        elif cur_status == "running":
                            # 未产生新日志阶段，输出心跳进度
                            stage_clean = re.sub(r"^\[.*?\]\s*", "", last_stage)
                            print_step(f"[{suite_name}] 任务持续进行中 (已耗时 {elapsed}s | 当前阶段: {CLR_YELLOW}{stage_clean}{CLR_RESET})")

                if is_finished:
                    if cur_status == "success":
                        vuln_count = cur_data.get("vuln_count", 0)
                        print_success(f"[{suite_name}] 扫描顺利完成! 耗时: {elapsed}s, 检出告警总数: {vuln_count}")
                        return task_id
                    else:
                        err_msg = cur_data.get("error", "无详细错误")
                        print_error(f"[{suite_name}] 扫描未能成功完成, 终态: {cur_status}, 原因: {err_msg}")
                        # 检查是否为致命基础设施/配置缺失错误
                        fatal_patterns = [
                            "no such file or directory",
                            "not found",
                            "executable file not found",
                            "codeql database create failed: fork/exec",
                            "database create failed"
                        ]
                        if any(pattern in err_msg.lower() for pattern in fatal_patterns):
                            raise FatalInfrastructureError(
                                f"检测到底层 SAST 执行环境关键依赖缺失！\n"
                                f"  • 错误详情: {err_msg}\n"
                                f"  • 诊断说明: devsecops-worker-sast 无法找到或执行 CodeQL 引擎。\n"
                                f"  • 解决建议: 请检查 configs/example.yaml 中的 scanner.codeql_path 与 codeql_queries 配置，\n"
                                f"            确保已安装适用于当前 Linux/WSL 环境的 CodeQL CLI 并赋予执行权限。"
                            )
                        return None

            time.sleep(self.poll_interval)

    def fetch_findings(self, task_id: int) -> List[Dict[str, Any]]:
        """提取指定扫描任务的结构化缺陷结果"""
        print_step(f"正在获取 TaskID={task_id} 的全部扫描漏洞结果...")
        findings = []
        page = 1
        per_page = 200

        while True:
            endpoint = f"/api/v1/scan/vulnerabilities?task_id={task_id}&page={page}&per_page={per_page}"
            status, res = self.client.request("GET", endpoint)
            if status != 200 or not isinstance(res, dict) or "data" not in res:
                break

            data_envelope = res["data"]
            records = data_envelope.get("data", [])
            if not records:
                break

            findings.extend(records)
            total = data_envelope.get("total", 0)
            if len(findings) >= total or len(records) < per_page:
                break
            page += 1

        print_success(f"共获取到 {len(findings)} 条有效扫描结果记录")
        return findings

    def evaluate_task(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """将扫描结果与真值比对并计算综合评测指标"""
        # 1. 提取每个测试用例命中的分类与规则
        # 映射结构: test_name -> set(hit_categories)
        hits_by_test: Dict[str, set] = {}
        for f in findings:
            file_path = f.get("file_path", "")
            match = re.search(r"(BenchmarkTest\d{5})", file_path, re.IGNORECASE)
            if not match:
                continue
            test_name = match.group(1)
            # 规整大小写
            test_name = f"BenchmarkTest{test_name[-5:]}"

            rule_id = (f.get("rule_id") or "").lower()
            rule_name = (f.get("rule_name") or "").lower()

            hit_cat = self.classify_finding(rule_id, rule_name)
            if hit_cat:
                if test_name not in hits_by_test:
                    hits_by_test[test_name] = set()
                hits_by_test[test_name].add(hit_cat)

        # 2. 逐分类计算指标与全局汇总
        category_metrics: Dict[str, MetricSummary] = {
            cat: MetricSummary() for cat in BENCHMARK_CATEGORIES
        }
        overall = MetricSummary()

        for test_name, gt in self.ground_truth.items():
            cat = gt.category
            if cat not in category_metrics:
                continue

            metric = category_metrics[cat]
            metric.total += 1
            overall.total += 1

            # 判定当前分类下是否命中告警
            hit_this_cat = (test_name in hits_by_test and cat in hits_by_test[test_name])

            if gt.real_vuln:
                # 真实存在漏洞
                if hit_this_cat:
                    metric.tp += 1
                    overall.tp += 1
                else:
                    metric.fn += 1
                    overall.fn += 1
            else:
                # 真实不存在漏洞 (安全代码/负样本)
                if hit_this_cat:
                    metric.fp += 1
                    overall.fp += 1
                else:
                    metric.tn += 1
                    overall.tn += 1

        # 3. 计算比率与综合得分
        self._calculate_ratios(overall)
        for cat, m in category_metrics.items():
            self._calculate_ratios(m)

        return {
            "overall": overall,
            "categories": category_metrics,
            "unique_tests_flagged": len(hits_by_test)
        }

    def _calculate_ratios(self, m: MetricSummary):
        positives = m.tp + m.fn
        negatives = m.fp + m.tn
        alerts = m.tp + m.fp

        m.tpr = (m.tp / positives) if positives > 0 else 0.0
        m.fpr = (m.fp / negatives) if negatives > 0 else 0.0
        m.precision = (m.tp / alerts) if alerts > 0 else 0.0
        if (m.precision + m.tpr) > 0:
            m.f1_score = 2 * (m.precision * m.tpr) / (m.precision + m.tpr)
        else:
            m.f1_score = 0.0

        m.youden_j = m.tpr - m.fpr
        m.owasp_score = round(m.youden_j * 100.0, 2)

    def classify_finding(self, rule_id: str, rule_name: str) -> Optional[str]:
        """将 CodeQL 规则 ID 或名称映射到 Benchmark 11 类分类"""
        combined = f"{rule_id} {rule_name}"
        for cat, meta in BENCHMARK_CATEGORIES.items():
            # 1. 匹配官方关键字
            for rk in meta["rules"]:
                if rk in combined:
                    return cat
            # 2. 匹配 CWE 编号
            for cwe_tag in meta["cwes"]:
                if cwe_tag in combined:
                    return cat
        return None


# ==================== 终端看板打印器 ====================
class TerminalScorecardPrinter:
    @staticmethod
    def print_comparison_scorecard(
        baseline_eval: Optional[Dict[str, Any]],
        targeted_eval: Optional[Dict[str, Any]],
        baseline_task_id: Optional[int],
        targeted_task_id: Optional[int]
    ):
        print_header("OWASP Benchmark SAST Evaluation Scorecard", emoji="🎯")

        # 1. 核心综合指标概览
        print(f"\n{CLR_WHITE}  📊 Global Benchmark Metrics Summary:{CLR_RESET}")
        header = f"  {'Metric / Suite':<28} | {'[Suite A] Baseline':<24} | {'[Suite B] Targeted CWE':<24}"
        divider = "  " + "-" * 81
        print(f"{CLR_BLUE}{header}{CLR_RESET}")
        print(f"{CLR_BLUE}{divider}{CLR_RESET}")

        def get_val(ev: Optional[Dict[str, Any]], attr: str, fmt: str = "{}") -> str:
            if not ev or "overall" not in ev:
                return "N/A"
            val = getattr(ev["overall"], attr)
            return fmt.format(val)

        t_base = f"Task #{baseline_task_id}" if baseline_task_id else "N/A"
        t_targ = f"Task #{targeted_task_id}" if targeted_task_id else "N/A"
        print(f"  {'Task Reference':<28} | {t_base:<24} | {t_targ:<24}")

        print(f"  {'Total Test Cases':<28} | {get_val(baseline_eval, 'total'):<24} | {get_val(targeted_eval, 'total'):<24}")
        print(f"  {'True Positives (TP)':<28} | {CLR_GREEN}{get_val(baseline_eval, 'tp'):<24}{CLR_RESET} | {CLR_GREEN}{get_val(targeted_eval, 'tp'):<24}{CLR_RESET}")
        print(f"  {'False Positives (FP)':<28} | {CLR_RED}{get_val(baseline_eval, 'fp'):<24}{CLR_RESET} | {CLR_RED}{get_val(targeted_eval, 'fp'):<24}{CLR_RESET}")
        print(f"  {'True Negatives (TN)':<28} | {get_val(baseline_eval, 'tn'):<24} | {get_val(targeted_eval, 'tn'):<24}")
        print(f"  {'False Negatives (FN)':<28} | {CLR_RED}{get_val(baseline_eval, 'fn'):<24}{CLR_RESET} | {CLR_RED}{get_val(targeted_eval, 'fn'):<24}{CLR_RESET}")

        tpr_a = get_val(baseline_eval, 'tpr', "{:.2%}")
        tpr_b = get_val(targeted_eval, 'tpr', "{:.2%}")
        print(f"  {'True Positive Rate (TPR)':<28} | {CLR_GREEN}{tpr_a:<24}{CLR_RESET} | {CLR_GREEN}{tpr_b:<24}{CLR_RESET}")

        fpr_a = get_val(baseline_eval, 'fpr', "{:.2%}")
        fpr_b = get_val(targeted_eval, 'fpr', "{:.2%}")
        print(f"  {'False Positive Rate (FPR)':<28} | {CLR_RED}{fpr_a:<24}{CLR_RESET} | {CLR_RED}{fpr_b:<24}{CLR_RESET}")

        prec_a = get_val(baseline_eval, 'precision', "{:.2%}")
        prec_b = get_val(targeted_eval, 'precision', "{:.2%}")
        print(f"  {'Precision (查准率)':<28} | {prec_a:<24} | {prec_b:<24}")

        f1_a = get_val(baseline_eval, 'f1_score', "{:.3f}")
        f1_b = get_val(targeted_eval, 'f1_score', "{:.3f}")
        print(f"  {'F1-Score':<28} | {f1_a:<24} | {f1_b:<24}")

        score_a = get_val(baseline_eval, 'owasp_score', "{:+.2f}%")
        score_b = get_val(targeted_eval, 'owasp_score', "{:+.2f}%")
        print(f"  {CLR_YELLOW}{'OWASP Score (Youden J)':<28}{CLR_RESET} | {CLR_YELLOW}{score_a:<24}{CLR_RESET} | {CLR_YELLOW}{score_b:<24}{CLR_RESET}")
        print(f"{CLR_BLUE}{divider}{CLR_RESET}")

        # 2. 分类别详细指标表格 (以靶向或 Baseline 主套件呈现)
        active_eval = targeted_eval or baseline_eval
        suite_title = "Suite B (Targeted CWE)" if targeted_eval else "Suite A (Baseline)"
        if active_eval and "categories" in active_eval:
            print(f"\n{CLR_WHITE}  📂 Detailed Breakdown by Vulnerability Category ({suite_title}):{CLR_RESET}")
            tbl_header = f"  {'Category':<14} | {'CWE':<6} | {'Total':<6} | {'TP':<5} | {'FP':<5} | {'FN':<5} | {'TPR':<8} | {'FPR':<8} | {'Score':<8}"
            tbl_div = "  " + "-" * 81
            print(f"{CLR_BLUE}{tbl_header}{CLR_RESET}")
            print(f"{CLR_BLUE}{tbl_div}{CLR_RESET}")

            for cat, meta in BENCHMARK_CATEGORIES.items():
                m: MetricSummary = active_eval["categories"].get(cat, MetricSummary())
                cwe_str = str(meta["cwe"])
                tpr_str = f"{m.tpr:.1%}"
                fpr_str = f"{m.fpr:.1%}"
                score_str = f"{m.owasp_score:+.1f}%"
                print(
                    f"  {cat:<14} | "
                    f"{cwe_str:<6} | "
                    f"{m.total:<6} | "
                    f"{CLR_GREEN}{m.tp:<5}{CLR_RESET} | "
                    f"{CLR_RED}{m.fp:<5}{CLR_RESET} | "
                    f"{m.fn:<5} | "
                    f"{CLR_GREEN}{tpr_str:<8}{CLR_RESET} | "
                    f"{CLR_RED}{fpr_str:<8}{CLR_RESET} | "
                    f"{CLR_YELLOW}{score_str:<8}{CLR_RESET}"
                )
            print(f"{CLR_BLUE}{tbl_div}{CLR_RESET}\n")


# ==================== Markdown 报告导出 ====================
def export_markdown_report(
    output_path: str,
    baseline_eval: Optional[Dict[str, Any]],
    targeted_eval: Optional[Dict[str, Any]],
    baseline_task_id: Optional[int],
    targeted_task_id: Optional[int],
    repo_url: str
):
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("# DevSecOps SAST - OWASP Benchmark v1.2 评测报告\n\n")
            f.write(f"- **评测执行时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"- **目标评测仓库**: `{repo_url}`\n")
            f.write(f"- **SAST 开箱套件 (Suite A)**: Task ID `{baseline_task_id or 'N/A'}`\n")
            f.write(f"- **CWE 靶向套件 (Suite B)**: Task ID `{targeted_task_id or 'N/A'}`\n\n")

            f.write("## 1. 核心指标对比看板\n\n")
            f.write("| 评估指标 | 开箱 Baseline 套件 | CWE 靶向强化套件 | 指标说明 |\n")
            f.write("| :--- | :---: | :---: | :--- |\n")

            def v(ev, attr, fmt="{}"):
                if not ev or "overall" not in ev:
                    return "N/A"
                return fmt.format(getattr(ev["overall"], attr))

            f.write(f"| **总测试用例数 (Total)** | {v(baseline_eval, 'total')} | {v(targeted_eval, 'total')} | 官方 Benchmark 1.2 标准用例 |\n")
            f.write(f"| **真正例 (TP / True Positive)** | {v(baseline_eval, 'tp')} | {v(targeted_eval, 'tp')} | 命中真实漏洞的用例数 |\n")
            f.write(f"| **假正例 (FP / False Positive)** | {v(baseline_eval, 'fp')} | {v(targeted_eval, 'fp')} | 误报的安全代码用例数 |\n")
            f.write(f"| **真反例 (TN / True Negative)** | {v(baseline_eval, 'tn')} | {v(targeted_eval, 'tn')} | 正确放过的安全代码用例数 |\n")
            f.write(f"| **假反例 (FN / False Negative)** | {v(baseline_eval, 'fn')} | {v(targeted_eval, 'fn')} | 漏报的真实漏洞用例数 |\n")
            f.write(f"| **真正例率 (TPR / Recall)** | {v(baseline_eval, 'tpr', '{:.2%}')} | {v(targeted_eval, 'tpr', '{:.2%}')} | $TP / (TP + FN)$ |\n")
            f.write(f"| **假正例率 (FPR / 误报率)** | {v(baseline_eval, 'fpr', '{:.2%}')} | {v(targeted_eval, 'fpr', '{:.2%}')} | $FP / (FP + TN)$ |\n")
            f.write(f"| **精确率 (Precision)** | {v(baseline_eval, 'precision', '{:.2%}')} | {v(targeted_eval, 'precision', '{:.2%}')} | $TP / (TP + FP)$ |\n")
            f.write(f"| **F1-Score** | {v(baseline_eval, 'f1_score', '{:.3f}')} | {v(targeted_eval, 'f1_score', '{:.3f}')} | 综合衡量准确与召回 |\n")
            f.write(f"| **OWASP 综合得分 (Youden's J)** | **{v(baseline_eval, 'owasp_score', '{:+.2f}%')}** | **{v(targeted_eval, 'owasp_score', '{:+.2f}%')}** | $(TPR - FPR) \\times 100\\%$ |\n\n")

            active_eval = targeted_eval or baseline_eval
            if active_eval and "categories" in active_eval:
                f.write("## 2. 11 项脆弱性分类详细分布\n\n")
                f.write("| 分类标识 | 对应 CWE | 用例总数 | TP (检出) | FP (误报) | FN (漏报) | TPR (召回率) | FPR (误报率) | OWASP 得分 |\n")
                f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
                for cat, meta in BENCHMARK_CATEGORIES.items():
                    m: MetricSummary = active_eval["categories"].get(cat, MetricSummary())
                    f.write(
                        f"| **{cat}** ({meta['name']}) | CWE-{meta['cwe']} | "
                        f"{m.total} | {m.tp} | {m.fp} | {m.fn} | "
                        f"{m.tpr:.2%} | {m.fpr:.2%} | **{m.owasp_score:+.2f}%** |\n"
                    )

            f.write("\n> 注：OWASP Score 基准得分为零代表算法效果等同于掷硬币随机猜测，得分大于 40% 为业界优秀白盒工具水平，大于 60% 达到高精密度级别。\n")
        print_success(f"Markdown 完整评估报告已导出至: {output_path}")
    except Exception as e:
        print_error(f"导出 Markdown 报告失败: {e}")


# ==================== 主入口与流程编排 ====================
def main():
    parser = argparse.ArgumentParser(description="DevSecOps Platform - OWASP Benchmark v1.2 SAST Evaluation")
    parser.add_argument("--server", default="http://localhost:22211", help="DevSecOps Server API base URL")
    parser.add_argument("--ground-truth", default="evaluations/owasp-benchmark/expectedresults-1.2.csv", help="Path to expectedresults-1.2.csv")
    parser.add_argument("--repo-url", default="https://github.com/OWASP-Benchmark/BenchmarkJava.git", help="Git clone URL of OWASP Benchmark repository")
    parser.add_argument("--repo-id", type=int, default=None, help="Existing repository ID on platform")
    parser.add_argument("--repo-branch", default="master", help="Git branch of benchmark repository")
    parser.add_argument("--poll-interval", type=int, default=15, help="Task polling interval in seconds")
    parser.add_argument("--timeout", type=int, default=7200, help="Max wait timeout per task in seconds")
    parser.add_argument("--output-json", default="evaluations/owasp-benchmark/benchmark_eval_result.json", help="Path to save evaluation JSON")
    parser.add_argument("--output-md", default="evaluations/owasp-benchmark/benchmark_eval_report.md", help="Path to save Markdown report")

    # 复用参数（防止任务因外部或中断需重复扫描）
    parser.add_argument("--reuse-task-baseline", type=int, default=None, help="Reuse an existing SAST task ID for Baseline")
    parser.add_argument("--reuse-task-targeted", type=int, default=None, help="Reuse an existing SAST task ID for Targeted")

    args = parser.parse_args()

    # 1. 启动与参数播报
    print_item("Target Server", args.server, indent=4, val_color=CLR_BLUE)
    print_item("Ground Truth File", args.ground_truth, indent=4, val_color=CLR_BLUE)
    print_item("Benchmark Repo URL", args.repo_url, indent=4, val_color=CLR_BLUE)
    print_item("Polling Interval", f"{args.poll_interval}s", indent=4, val_color=CLR_BLUE)
    print_item("Timeout Per Task", f"{args.timeout}s ({args.timeout // 60}m)", indent=4, val_color=CLR_BLUE)

    evaluator = BenchmarkEvaluator(
        server_url=args.server,
        ground_truth_path=args.ground_truth,
        repo_url=args.repo_url,
        repo_branch=args.repo_branch,
        custom_repo_id=args.repo_id,
        poll_interval=args.poll_interval,
        max_wait_seconds=args.timeout,
    )

    # 2. 加载真值表与预检
    if not evaluator.load_ground_truth():
        sys.exit(1)

    if not evaluator.preflight_check():
        sys.exit(1)

    # 3. 确认基准仓库存在
    if not evaluator.ensure_repository():
        sys.exit(1)

    baseline_task_id = args.reuse_task_baseline
    targeted_task_id = args.reuse_task_targeted

    baseline_eval = None
    targeted_eval = None

    # 4. 执行套件 A：开箱默认 Baseline 套件
    print(f"\n{CLR_WHITE}-------------------------------------------------------------------------------------{CLR_RESET}")
    print_step("【阶段 1/2】开始评估 Suite A: 开箱默认 Baseline 套件 (java-security-extended)")
    try:
        if not baseline_task_id:
            baseline_task_id = evaluator.submit_and_wait(
                suite_name="Suite A (Baseline)",
                rule_profile="baseline",
                rules=[]
            )

        if baseline_task_id:
            findings_a = evaluator.fetch_findings(baseline_task_id)
            baseline_eval = evaluator.evaluate_task(findings_a)
            print_success(f"Suite A 评估完毕! 检出用例覆盖数: {baseline_eval['unique_tests_flagged']}")
        else:
            print_warning("Suite A 未能成功获取有效 Task ID，跳过该套件指标计算，保持后续套件继续。")
    except FatalInfrastructureError as fie:
        print_error(f"\n{fie}")
        print_error("由于底层基础设施缺失，评测驱动已主动熔断终止，请配置正确环境后再试。\n")
        sys.exit(2)
    except Exception as e:
        print_error(f"Suite A 执行异常 (已容错捕获，不影响 Suite B): {e}")

    # 5. 执行套件 B：CWE 靶向强化套件
    print(f"\n{CLR_WHITE}-------------------------------------------------------------------------------------{CLR_RESET}")
    print_step("【阶段 2/2】开始评估 Suite B: CWE 靶向强化套件 (动态生成 11 项 OWASP CWE 规则)")
    try:
        if not targeted_task_id:
            targeted_task_id = evaluator.submit_and_wait(
                suite_name="Suite B (Targeted CWE)",
                rule_profile="baseline",
                rules=ALL_BENCHMARK_CWES
            )

        if targeted_task_id:
            findings_b = evaluator.fetch_findings(targeted_task_id)
            targeted_eval = evaluator.evaluate_task(findings_b)
            print_success(f"Suite B 评估完毕! 检出用例覆盖数: {targeted_eval['unique_tests_flagged']}")
        else:
            print_warning("Suite B 未能成功获取有效 Task ID。")
    except FatalInfrastructureError as fie:
        print_error(f"\n{fie}")
        print_error("由于底层基础设施缺失，评测驱动已主动熔断终止。\n")
        sys.exit(2)
    except Exception as e:
        print_error(f"Suite B 执行异常: {e}")

    # 6. 终端美化看板呈现
    TerminalScorecardPrinter.print_comparison_scorecard(
        baseline_eval=baseline_eval,
        targeted_eval=targeted_eval,
        baseline_task_id=baseline_task_id,
        targeted_task_id=targeted_task_id
    )

    # 7. 导出产物 (JSON 与 Markdown 报告)
    export_markdown_report(
        output_path=args.output_md,
        baseline_eval=baseline_eval,
        targeted_eval=targeted_eval,
        baseline_task_id=baseline_task_id,
        targeted_task_id=targeted_task_id,
        repo_url=args.repo_url
    )

    # 导出结构化结果 JSON
    result_data = {
        "metadata": {
            "timestamp": time.time(),
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "server": args.server,
            "repo_url": args.repo_url,
            "baseline_task_id": baseline_task_id,
            "targeted_task_id": targeted_task_id,
        },
        "baseline": _serialize_eval(baseline_eval),
        "targeted": _serialize_eval(targeted_eval),
    }
    try:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        print_success(f"结构化数据已保存至: {args.output_json}")
    except Exception as e:
        print_error(f"保存 JSON 产物失败: {e}")

def _serialize_eval(ev: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not ev:
        return None
    res = {
        "unique_tests_flagged": ev.get("unique_tests_flagged", 0),
        "overall": ev["overall"].__dict__ if "overall" in ev else {},
        "categories": {}
    }
    for k, v in ev.get("categories", {}).items():
        res["categories"][k] = v.__dict__
    return res

if __name__ == "__main__":
    main()
