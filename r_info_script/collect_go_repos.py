#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Go 开源仓库搜集、查重、0-day CVE 潜在漏洞评估与入队扫描脚本
支持自定义 CodeQL 规则套件 (--query-suite) 以及是否启用 AI 语义验证 (--disable-ai)。
支持通过 LLM 将宏观目标自动拆解为原子化子任务并分步执行。
"""

import os
import sys
import json
import time
import urllib.request
import urllib.parse
import urllib.error
import argparse
from typing import List, Dict, Any, Tuple

# 避免 Windows 终端输出 GBK 编码报错
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.json")
LOCAL_YAML_PATH = os.path.join(PROJECT_ROOT, "configs", "config.local.yaml")

def parse_simple_yaml(file_path: str) -> Dict[str, Any]:
    res = {}
    if not os.path.exists(file_path):
        return res
        
    current_section = None
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.split("#")[0].rstrip()
                if not line_str or line_str.isspace():
                    continue
                if not line_str.startswith(" ") and ":" in line_str:
                    current_section = line_str.split(":")[0].strip()
                    if current_section not in res:
                        res[current_section] = {}
                elif line_str.startswith("  ") and ":" in line_str and current_section:
                    parts = line_str.strip().split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip().strip('"').strip("'")
                    res[current_section][k] = v
    except Exception as e:
        print(f"[WARN] 解析 YAML 配置文件失败: {e}")
    return res

def load_config(config_path: str) -> Dict[str, Any]:
    cfg = {
        "backend_url": "http://localhost:22211",
        "github_token": os.getenv("GITHUB_TOKEN", ""),
        "llm_api_key": os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY", ""),
        "llm_base_url": os.getenv("OPENAI_BASE_URL", "https://api.deepseek.com"),
        "llm_model": os.getenv("OPENAI_MODEL", "deepseek-chat"),
        "min_stars": 20,
        "max_repos_per_query": 10,
        "query_suite": "",
        "use_ai_verification": True,
        "macro_goal": "搜集正在活跃维护、具备真实业务逻辑的 Go 语言开源应用与组件 (如 CMS、管理后台、API 网关、微服务平台、文件传输系统)，筛选具备 0-day 漏洞挖掘价值与 CVE 申请潜力的目标"
    }

    yaml_cfg = parse_simple_yaml(LOCAL_YAML_PATH)
    if "server" in yaml_cfg and "port" in yaml_cfg["server"]:
        port = yaml_cfg["server"]["port"]
        cfg["backend_url"] = f"http://localhost:{port}"
    if "openai" in yaml_cfg:
        if yaml_cfg["openai"].get("api_key"):
            cfg["llm_api_key"] = yaml_cfg["openai"]["api_key"]
        if yaml_cfg["openai"].get("base_url"):
            cfg["llm_base_url"] = yaml_cfg["openai"]["base_url"]
        if yaml_cfg["openai"].get("model"):
            cfg["llm_model"] = yaml_cfg["openai"]["model"]

    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                json_cfg = json.load(f)
                for k, v in json_cfg.items():
                    if v or k not in cfg:
                        cfg[k] = v
        except Exception as e:
            print(f"[WARN] 加载 JSON 配置文件失败: {e}")

    return cfg

def http_request(url: str, method: str = "GET", headers: Dict[str, str] = None, data: Dict[str, Any] = None, timeout: int = 15, retries: int = 2) -> Tuple[int, Dict[str, Any]]:
    if headers is None:
        headers = {}
    headers["User-Agent"] = "DevSecOps-Go-Repo-Collector/1.0"
    
    encoded_data = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        encoded_data = json.dumps(data).encode("utf-8")
        
    proxy_handler = urllib.request.ProxyHandler()
    opener = urllib.request.build_opener(proxy_handler)

    last_err = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
        try:
            with opener.open(req, timeout=timeout) as response:
                status_code = response.status
                body = response.read().decode("utf-8")
                try:
                    json_body = json.loads(body)
                except Exception:
                    json_body = {"raw": body}
                return status_code, json_body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try:
                json_body = json.loads(body)
            except Exception:
                json_body = {"error": body}
            return e.code, json_body
        except Exception as e:
            last_err = str(e)
            time.sleep(1)

    return 500, {"error": last_err or "Network error"}

def normalize_git_url(url: str) -> str:
    u = (url or "").strip().lower()
    if u.endswith(".git"):
        u = u[:-4]
    u = u.rstrip("/")
    if u.startswith("git@github.com:"):
        u = "https://github.com/" + u[len("git@github.com:"):]
    return u

def sanitize_github_query(raw_query: str) -> str:
    q = raw_query.strip()
    q = q.replace('"', '').replace("'", "")
    if "language:Go" not in q and "language:go" not in q:
        q = "language:Go " + q
    return q

class LLMTaskDecomposer:
    """LLM 动态任务拆解器：针对可申请 0-day CVE 的真实开源项目进行智能任务拆解"""
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model

    def decompose(self, macro_goal: str) -> List[Dict[str, Any]]:
        print(f"\n[LLM 任务拆解引擎] 正在分析 CVE 0-day 挖掘宏观目标: '{macro_goal}' ...")
        
        prompt = f"""你是一名资深漏洞挖掘专家与 DevSecOps 智能体架构师。
用户的核心诉求是："{macro_goal}"。

关键约束与语法要求：
1. 目标是寻找【真实的、易于部署与本地复现的 Go 语言开源应用】（如 Go CMS、博客系统、管理后台、文件存储传输系统）。
2. 严禁生成关于 ERP、CRM、大型 API 网关或复杂微服务框架的搜索子任务（因为此类大型中间件部署复杂、PoC 复现极不方便）！
3. "search_query" 必须遵守 GitHub API 简单检索语法，格式为简单的关键词组合！格式范例：`language:Go cms stars:>15 pushed:>2023-01-01 archived:false`
4. 严禁在 search_query 中使用复杂的 NOT 逻辑、过多的括号嵌套或复杂的带引号短语，避免 GitHub API 返回 422 错误！排除靶场和历史 CVE 的过滤逻辑将由后台 LLM 语义裁决器处理。

请将该目标拆解为 2 到 3 个 GitHub API 搜索子任务。
每个子任务包含字段：
- "subtask_id": 1, 2...
- "title": 简洁的子任务标题
- "description": 子任务意图
- "search_query": 极简合法的 GitHub 检索语法 (如: `language:Go cms stars:>15 pushed:>2023-01-01 archived:false`)
- "focus_cve_types": 潜在可挖掘并申请 CVE 的漏洞类型（如: ["RCE", "Arbitrary-File-Upload", "SQLi", "Path-Traversal"]）

请仅输出标准的 JSON 数组，不要添加 Markdown ```json 代码块。"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }

        url = f"{self.base_url}/chat/completions"
        code, resp = http_request(url, method="POST", headers=headers, data=payload, timeout=20)
        
        if code == 200 and "choices" in resp and len(resp["choices"]) > 0:
            content = resp["choices"][0]["message"]["content"].strip()
            try:
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                tasks = json.loads(content.strip())
                print(f"[Success] LLM 成功将目标拆解为 {len(tasks)} 个面向 0-day CVE 挖掘的原子化子任务！")
                return tasks
            except Exception as e:
                print(f"[WARN] LLM 拆解响应解析异常 ({e})，使用备用 0-day 策略队列")
        else:
            print(f"[WARN] LLM 接口响应状态 HTTP {code}，使用备用 0-day 策略队列")

        return [
            {
                "subtask_id": 1,
                "title": "检索近期活跃的 Go 语言开源 CMS / 博客内容管理系统",
                "search_query": "language:Go cms stars:>15 pushed:>2023-01-01 archived:false",
                "focus_cve_types": ["Arbitrary-File-Upload", "SQLi", "RCE"]
            },
            {
                "subtask_id": 2,
                "title": "检索轻量级 Go 文件传输与云存储管理服务",
                "search_query": "language:Go file sharing stars:>20 pushed:>2023-01-01 archived:false",
                "focus_cve_types": ["Path-Traversal", "Arbitrary-File-Upload", "RCE"]
            },
            {
                "subtask_id": 3,
                "title": "检索基于 Gin/Fiber 框架构建的简易后台管理系统",
                "search_query": "language:Go admin panel stars:>20 pushed:>2023-01-01 archived:false",
                "focus_cve_types": ["RCE", "Auth-Bypass", "SQLi"]
            }
        ]

class LLMEvaluator:
    """LLM 语义裁决器：评估项目漏洞隐患，"""
    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model

    def evaluate_cve_potential(self, repo: Dict[str, Any], focus_cve_types: List[str] = None) -> Dict[str, Any]:
        if not self.api_key:
            return {
                "score": 75,
                "reason": "未配置 LLM API Key，使用默认策略入队进行 SAST 静态代码扫描",
                "recommended_profile": "zero_day_only"
            }

        cve_str = ", ".join(focus_cve_types) if focus_cve_types else "RCE, SQLi, File-Upload, SSRF"
        prompt = f"""你是一名高水平漏洞挖掘专家与 CVE 审核员。请评估以下 Go 开源项目的【新 CVE 申请潜力与 0-day 挖掘价值】。

仓库名称: {repo.get('full_name')}
项目描述: {repo.get('description')}
Stars: {repo.get('stargazers_count')}
Topics: {repo.get('topics', [])}
主页地址: {repo.get('html_url')}

评估过滤原则：
1. 严格剔除（打 0 分）：如果是故意设计的教学漏洞靶场 (如 vulnerable-app, testbed, ctf, juice-shop, webgoat)、或者只是已知历史 CVE 漏洞记录集合 (如 cve-2022, cve-2023)，严禁入选！
2. 评估高潜力（打高分）：如果是真实的、生产可用的 Go 业务应用/系统/中间件，存在参数解析、文件上传或命令执行等，具备挖掘未公开 0-day 并申请新 CVE 价值的。

请以 JSON 格式输出评估结果：
1. "score": 整数(0-100)，代表申请新 CVE 的潜力分。低于 50 分将被自动过滤。
2. "reason": 一句话中文总结评估理由 (说明为什么适合/不适合挖掘 0-day CVE)。
3. "recommended_profile": 扫描策略 ("zero_day_only" 或 "baseline")。

仅输出合法 JSON 字符串，不要包含 Markdown 代码块。"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }

        url = f"{self.base_url}/chat/completions"
        code, resp = http_request(url, method="POST", headers=headers, data=payload, timeout=20)
        if code == 200 and "choices" in resp and len(resp["choices"]) > 0:
            content = resp["choices"][0]["message"]["content"].strip()
            try:
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                return json.loads(content.strip())
            except Exception as e:
                return {"score": 70, "reason": f"LLM 响应解析失败: {e}", "recommended_profile": "zero_day_only"}
        return {"score": 60, "reason": f"LLM API 响应状态 HTTP {code}", "recommended_profile": "zero_day_only"}

def fetch_github_repos(keyword: str, token: str, max_count: int) -> List[Dict[str, Any]]:
    clean_query = sanitize_github_query(keyword)
    encoded_query = urllib.parse.quote(clean_query)
    url = f"https://api.github.com/search/repositories?q={encoded_query}&sort=stars&order=desc&per_page={max_count}"
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    
    code, resp = http_request(url, headers=headers, timeout=15, retries=2)
    if code == 200 and "items" in resp:
        return resp["items"]
    else:
        print(f"  [WARN] GitHub API 查询失败 [{clean_query}]: HTTP {code}, 信息={resp.get('message', resp.get('error'))}")
        return []

def get_existing_repos(backend_url: str) -> List[Dict[str, Any]]:
    url = f"{backend_url.rstrip('/')}/api/v1/repos/list?page=1&per_page=500"
    code, resp = http_request(url, timeout=10)
    if code == 200 and resp.get("data", {}).get("data"):
        return resp["data"]["data"]
    return []

def register_and_queue_scan(backend_url: str, repo_info: Dict[str, Any], eval_res: Dict[str, Any], custom_query_suite: str = "", use_ai: bool = True) -> Tuple[bool, str]:
    base = backend_url.rstrip('/')
    
    reg_url = f"{base}/api/v1/repos"
    branch = repo_info.get("default_branch") or "main"
    clone_url = repo_info.get("clone_url") or (repo_info.get("html_url") + ".git")
    
    payload_repo = {
        "name": repo_info.get("name") or repo_info.get("full_name").replace("/", "-"),
        "url": clone_url,
        "language": "go",
        "branch": branch,
        "stars": repo_info.get("stargazers_count", 0),
        "auth_type": "none"
    }
    
    code, resp = http_request(reg_url, method="POST", data=payload_repo, timeout=10)
    if code != 200 and code != 201:
        err_msg = resp.get("error", "注册仓库失败")
        return False, f"注册仓库失败 HTTP {code}: {err_msg}"
        
    repo_id = resp.get("data", {}).get("id")
    if not repo_id:
        return False, "注册仓库成功但未返回有效 repo_id"
        
    scan_url = f"{base}/api/v1/scan/tasks"
    payload_scan = {
        "repo_id": repo_id,
        "language": "go",
        "branch": branch,
        "rule_profile": eval_res.get("recommended_profile", "zero_day_only"),
        "use_ai_verification": use_ai
    }

    if custom_query_suite:
        payload_scan["query_suite"] = custom_query_suite
    
    code_scan, resp_scan = http_request(scan_url, method="POST", data=payload_scan, timeout=10)
    if code_scan == 200 or code_scan == 201:
        task_id = resp_scan.get("data", {}).get("task_id")
        queue_id = resp_scan.get("data", {}).get("queue_id")
        suite_info = f", QLSuite='{custom_query_suite}'" if custom_query_suite else ""
        ai_info = f", AI验证={'开启' if use_ai else '关闭'}"
        return True, f"注册并成功提交 SAST 扫描 (RepoID={repo_id}, TaskID={task_id}{suite_info}{ai_info})"
    else:
        return False, f"仓库注册成功 (ID={repo_id})，但入队扫描失败: {resp_scan.get('error')}"

def main():
    parser = argparse.ArgumentParser(description="Go 开源仓库 0-day CVE 潜在目标搜集、查重与入队工具")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="配置文件路径")
    parser.add_argument("--dry-run", action="store_true", help="仅搜索与评估，不实际入队")
    parser.add_argument("--goal", default=None, help="自定义 0-day 搜集目标说明")
    parser.add_argument("--query-suite", default=None, help="指定使用的 CodeQL 规则套件 (.ql / .qls)")
    parser.add_argument("--disable-ai", action="store_true", help="关闭 LLM 漏洞验证复现功能")
    args = parser.parse_args()

    cfg = load_config(args.config)
    backend_url = cfg.get("backend_url", "http://localhost:22211")
    github_token = cfg.get("github_token", "")
    max_per_query = cfg.get("max_repos_per_query", 10)
    macro_goal = args.goal or cfg.get("macro_goal")
    
    query_suite = args.query_suite if args.query_suite is not None else cfg.get("query_suite", "")
    use_ai = False if args.disable_ai else cfg.get("use_ai_verification", True)

    decomposer = LLMTaskDecomposer(
        api_key=cfg.get("llm_api_key", ""),
        base_url=cfg.get("llm_base_url", "https://api.deepseek.com"),
        model=cfg.get("llm_model", "deepseek-chat")
    )
    
    evaluator = LLMEvaluator(
        api_key=cfg.get("llm_api_key", ""),
        base_url=cfg.get("llm_base_url", "https://api.deepseek.com"),
        model=cfg.get("llm_model", "deepseek-chat")
    )

    print("==================================================================")
    print("[Init] Go 开源仓库潜在漏洞目标搜集与入队")
    print(f"后端服务地址: {backend_url}")
    print(f"LLM 模型: {cfg.get('llm_model')} (API Key 状态: {'已配置' if cfg.get('llm_api_key') else '未配置(降维模式)'})")
    print(f"CodeQL 规则套件: {query_suite if query_suite else '默认策略库 (zero_day_only)'}")
    print(f"AI 语义漏洞验证: {'开启' if use_ai else '关闭'}")
    print("==================================================================")

    subtasks = decomposer.decompose(macro_goal)
    print(f"\n[Plan] LLM 0-day 搜集子任务队列规划完成 (共 {len(subtasks)} 项):")
    for st in subtasks:
        print(f"  └─ [子任务 {st.get('subtask_id')}] {st.get('title')}\n     (Query: {st.get('search_query')})")

    print("\n[Step 1] 正在调取 DevSecOps 数据库已存在的仓库进行查重集合构建...")
    existing_repos = get_existing_repos(backend_url)
    existing_urls = set()
    existing_names = set()
    
    for r in existing_repos:
        if "url" in r:
            existing_urls.add(normalize_git_url(r["url"]))
        if "name" in r:
            existing_names.add(r["name"].lower())
            
    print(f"[OK] 已加载 {len(existing_repos)} 个数据库现有仓库条目用于精确查重。")

    new_queued_count = 0
    skipped_count = 0
    total_candidates = 0
    logs = []

    print("\n[Step 2] 开始按队列逐步执行 0-day 搜集子任务...")
    
    for idx, st in enumerate(subtasks, 1):
        st_id = st.get("subtask_id", idx)
        title = st.get("title", f"子任务 {st_id}")
        raw_query = st.get("search_query", "language:Go cms")
        focus_types = st.get("focus_cve_types", [])

        print(f"\n------------------------------------------------------------------")
        print(f"[Executing {idx}/{len(subtasks)}] {title}")
        print(f"   检索 Query: [{raw_query}] | 关注 0-day 漏洞类型: {focus_types}")
        print(f"------------------------------------------------------------------")

        items = fetch_github_repos(raw_query, github_token, max_count=max_per_query)
        total_candidates += len(items)

        for repo in items:
            repo_url = normalize_git_url(repo.get("clone_url") or repo.get("html_url"))
            name = repo.get("name", "").lower()
            full_name = repo.get("full_name")
            
            if repo_url in existing_urls or name in existing_names:
                print(f"  [Skip Existing] 仓库: {full_name} ({repo_url})")
                skipped_count += 1
                logs.append(f"SKIP: {full_name}")
                continue

            eval_res = evaluator.evaluate_cve_potential(repo, focus_types)
            score = eval_res.get("score", 0)
            reason = eval_res.get("reason", "")
            
            print(f"\n  [Target Found] {full_name}")
            print(f"    ├─ Git URL: {repo.get('clone_url')}")
            print(f"    ├─ Stars: {repo.get('stargazers_count')}")
            print(f"    ├─ LLM 0-day CVE 申请潜力分: {score}/100")
            print(f"    └─ 裁决说明: {reason}")

            if score < 50:
                print(f"    [Skip Low Score / Testbed] LLM 识别为靶场或 low-score 项目，不予入队。")
                skipped_count += 1
                continue

            if args.dry_run:
                print(f"    [Dry-Run] 仅做计算评估，跳过实际入队。")
                continue

            success, msg = register_and_queue_scan(backend_url, repo, eval_res, query_suite, use_ai)
            if success:
                print(f"    [Queued] {msg}")
                new_queued_count += 1
                existing_urls.add(repo_url)
                logs.append(f"QUEUED: {full_name} -> {msg}")
            else:
                print(f"    [Queue Error] {msg}")
                logs.append(f"FAILED: {full_name} -> {msg}")

        time.sleep(1)

    print("\n==================================================================")
    print("[Summary]  搜集与入队总结报告：")
    print(f" - LLM 拆解子任务总数: {len(subtasks)}")
    print(f" - 检索候选总数: {total_candidates}")
    print(f" - 查重/低潜力/靶场过滤跳过: {skipped_count}")
    print(f" - 新增成功入队 0-day SAST 扫描: {new_queued_count}")
    print(f" - 扫描配置: QL套件='{query_suite if query_suite else '默认'}', AI验证={'开启' if use_ai else '关闭'}")
    print("==================================================================")

    summary_path = os.path.join(SCRIPT_DIR, "discovery_summary.log")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"Zero-Day CVE Discovery Summary Log - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n".join(logs))
    print(f"日志已保存至: {summary_path}")

if __name__ == "__main__":
    main()
