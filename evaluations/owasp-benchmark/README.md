# OWASP Benchmark v1.2 自动化 SAST 评测与量化体系

本指南为当前 `devsecops` 平台提供标准的 **端到端（End-to-End Live）静态代码分析 (SAST) 评测与量化工具链**，采用国际权威软件保障基准 **OWASP Benchmark for Java (v1.2)** 作为标准真值输入。

---

## 一、评测基准与量化公式体系

### 1.1 OWASP Benchmark 1.2 概况
- **测试用例总数**：2,740 个独立 Java 漏洞与负样本测试用例（`BenchmarkTest00001.java` ~ `BenchmarkTest02740.java`）。
- **样本分布**：包含 **1,415 个真漏洞用例 (True Positives 待测点)** 和 **1,325 个安全对照用例 (True Negatives 负样本)**。
- **覆盖 11 类标准 CWE 弱点**：
  1. `cmdi` (CWE-78): 命令注入
  2. `crypto` (CWE-327): 弱加密算法
  3. `hash` (CWE-328): 弱哈希算法
  4. `ldapi` (CWE-90): LDAP 注入
  5. `pathtraver` (CWE-22): 路径遍历
  6. `securecookie` (CWE-614): 不安全 Cookie 标志
  7. `sqli` (CWE-89): SQL 注入
  8. `trustbound` (CWE-501): 信任边界违规
  9. `weakrand` (CWE-330): 不安全伪随机数
  10. `xpathi` (CWE-643): XPath 注入
  11. `xss` (CWE-79): 跨站脚本攻击

---

### 1.2 量化评价指标与公式

对于每个用例 $i \in \{1 \dots 2740\}$，将扫描器对该用例在特定类别下的检出情况与标准真值表（`expectedresults-1.2.csv`）进行比对：

| 混淆矩阵 (Confusion Matrix) | 真值：有漏洞 (Real = True) | 真值：无漏洞/安全代码 (Real = False) |
| :--- | :---: | :---: |
| **工具报出告警 (Alerted)** | **真正例 (TP, True Positive)** | **假正例 (FP, False Positive / 误报)** |
| **工具未报告警 (No Alert)** | **假反例 (FN, False Negative / 漏报)** | **真反例 (TN, True Negative / 正确忽略)** |

#### 核心量化指标：
1. **真正例率 / 召回率 (TPR / True Positive Rate / Recall)**：
   $$TPR = \frac{TP}{TP + FN}$$
   衡量工具对真实漏洞的检出广度。
2. **假正例率 / 误报率 (FPR / False Positive Rate / Fall-out)**：
   $$FPR = \frac{FP}{FP + TN}$$
   衡量工具对安全代码的误报程度。
3. **查准率 (Precision)**：
   $$Precision = \frac{TP}{TP + FP}$$
4. **调和均值 (F1-Score)**：
   $$F1 = 2 \times \frac{Precision \times TPR}{Precision + TPR}$$
5. **尤登指数 / OWASP 综合评分 (Youden's Index $J$ / OWASP Score)**：
   $$J = TPR - FPR = \frac{TP}{TP + FN} - \frac{FP}{FP + TN}$$
   $$OWASP\ Score = J \times 100\%$$

> [!IMPORTANT]
> **为什么不能只看检出率 (TPR)？**  
> 如果一个工具无脑将所有 2,740 个文件全部标记为存在漏洞，其 TPR 会高达 100%，但其 FPR 同样高达 100%，此时 $J = 100\% - 100\% = 0\%$（得分等同于随机猜测抛硬币）。
> **Youden's J** 是目前安全学术界与工业界最严格公正的指标，只有“高检出且低误报”的工具才能获得高分。商业/开源顶尖引擎在 Benchmark 1.2 的得分通常在 30%~60% 区间。

---

## 二、评测方案：双套件对比架构

本评测驱动设计了**双套件对比（Dual-Suite Comparison）**，量化评估平台开箱默认能力与规则调优后的差异：

| 套件 | 规则策略 | 机制与设计目的 |
| :--- | :--- | :--- |
| **Suite A: 开箱默认 Baseline** | `rule_profile: "baseline"`，无额外 rules | 调用 CodeQL 官方标准 `java-security-extended.qls`，评估平台在开发者开箱即用状态下的真实表现与底噪水平。 |
| **Suite B: CWE 靶向强化套件** | `rules: ["cwe-022", "cwe-078", "cwe-089", ...]` | 触发平台的**动态 QLS 生成能力**（`internal/sast/scanner/codeql.go` 中的 `generateDynamicQLS`），仅针对 Benchmark 覆盖的 11 类 CWE 注入靶向规则，剔除无关通用编码异味。 |

---

## 三、文件组织

```text
evaluations/owasp-benchmark/
├── expectedresults-1.2.csv         # OWASP 官方 2,740 个用例的预期真值表 (已离线固化)
├── eval_benchmark.py               # 核心端到端评估驱动器 (含双套件、容错隔离、ANSI 看板与报告导出)
├── run_evaluation.sh               # 一键评估复现 Shell 脚本
├── benchmark_eval_report.md        # 自动生成的 Markdown 格式评估报告 (运行后产出)
└── benchmark_eval_result.json      # 结构化评估结果 (包含 TP/FP/TN/FN/TPR/FPR 细粒度数据)
```

---

## 四、快速启动与操作指南

### 4.1 环境准备
1. 启动 PostgreSQL 与 Redis。
2. 启动平台服务端与 SAST 扫描执行节点：
   ```bash
   ./devsecops-server --config configs/example.yaml
   ./devsecops-worker-sast --config configs/example.yaml
   ```

### 4.2 一键执行评测
在项目根目录或评测目录下运行：

```bash
# 方式 1: 直接使用包装脚本一键执行
./evaluations/owasp-benchmark/run_evaluation.sh

# 方式 2: 使用 Python 脚本灵活传参
python3 evaluations/owasp-benchmark/eval_benchmark.py \
  --server http://localhost:22211 \
  --repo-url https://github.com/OWASP-Benchmark/BenchmarkJava.git \
  --timeout 7200
```

### 4.3 常用参数说明
- `--server`: 平台接口基地址（默认 `http://localhost:22211`）。
- `--repo-id`: 若平台中已录入该仓库，可显式指定其 ID，跳过自动创建。
- `--poll-interval`: 轮询任务状态的时间间隔（默认 15s）。
- `--timeout`: 单套件最大等待超时时间（秒，默认 7200s）。
- `--reuse-task-baseline <TASK_ID>`: 复用已有 Baseline 任务 ID，无需重新编译扫描（极度适合重试或二次比对分析）。
- `--reuse-task-targeted <TASK_ID>`: 复用已有 Targeted 任务 ID。

---

## 五、边界情况与健壮性保障 (Resilience & Edge Cases)

本自动化脚本在设计上深度遵循了工业级工程规范，针对端到端长周期任务做好了全面的边界处理：

1. **真值离线本地化**：
   - 官方真值 `expectedresults-1.2.csv` 已随版本完整打包固化在仓库中，脚本优先读取本地文件，彻底避免受 GitHub 网络波动导致的评测阻断。
2. **前后任务强隔离（Non-blocking Fault Isolation）**：
   - Suite A 与 Suite B 采用独立 `try...except` 沙盒包裹。即使 Suite A 编译失败或因超时退出，错误会被安全捕获并记录，**绝对不会阻断 Suite B 的正常执行与最终看板生成**。
3. **断点复用与抗中断机制**：
   - CodeQL 在 2,740 个类的完整编译耗时较长。若任务此前已经由平台执行成功，只需传入 `--reuse-task-baseline <ID>` 或 `--reuse-task-targeted <ID>`，脚本将直接提取已持久化的漏洞结果并在数秒内完成打分与报告输出。
4. **多告警去重与规整**：
   - 单个测试用例若命中多条同类规则，算法自动聚合去重为 1 次有效检出，严防多条告警造成 TP 或 FP 虚高膨胀。
5. **ANSI 色彩终端看板与 Markdown 双输出**：
   - 评测完成后，不仅在终端以符合 `RULE[user_global]` 规范的 ANSI 青绿红黄色调输出对齐报表，还会同时持久化结构化 JSON 与 Markdown 完整报告。
