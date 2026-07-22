# Go 开源仓库 0-day CVE 潜在漏洞目标搜集、查重与入队工具

本工具实现了 **LLM 驱动的 0-day CVE 漏洞目标拆解与自动化扫描提交** 架构。

## 核心配置与参数扩展

你可以在 [config.json](file:///c:/Users/10278/Desktop/2026-07/devsecops/r_info_script/config.json) 或命令行参数中**自由指定使用的 CodeQL 规则套件及是否启动 AI 大模型二次复现验证**。

### 命令行参数说明：

1. **指定 CodeQL 规则套件 (`--query-suite`)**：
   ```bash
   python collect_go_repos.py --query-suite "rules/codeql/rce.ql"
   ```
2. **关闭 / 开启 AI 大模型复现验证 (`--disable-ai`)**：
   ```bash
   python collect_go_repos.py --disable-ai
   ```
3. **组合使用 (指定规则套件 + 自定义 0-day 目标 + 试运行)**：
   ```bash
   python collect_go_repos.py --query-suite "rules/codeql/rce.ql" --goal "搜集可能存在 RCE 命令注入漏洞的 Go Web 网关" --dry-run
   ```

## 一键快捷批处理
- Windows: 双击 `run_discovery.bat`
- Linux / macOS: 执行 `./run_discovery.sh`
