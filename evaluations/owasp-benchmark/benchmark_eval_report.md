# DevSecOps SAST - OWASP Benchmark v1.2 评测报告

- **评测执行时间**: 2026-11-02 14:00:59
- **目标评测仓库**: `https://github.com/OWASP-Benchmark/BenchmarkJava.git`
- **SAST 开箱套件 (Suite A)**: Task ID `14`
- **CWE 靶向套件 (Suite B)**: Task ID `16`

## 1. 核心指标对比看板

| 评估指标 | 开箱 Baseline 套件 | CWE 靶向强化套件 | 指标说明 |
| :--- | :---: | :---: | :--- |
| **总测试用例数 (Total)** | 2740 | 2740 | 官方 Benchmark 1.2 标准用例 |
| **真正例 (TP / True Positive)** | 1415 | 1415 | 命中真实漏洞的用例数 |
| **假正例 (FP / False Positive)** | 531 | 531 | 误报的安全代码用例数 |
| **真反例 (TN / True Negative)** | 794 | 794 | 正确放过的安全代码用例数 |
| **假反例 (FN / False Negative)** | 0 | 0 | 漏报的真实漏洞用例数 |
| **真正例率 (TPR / Recall)** | 100.00% | 100.00% | $TP / (TP + FN)$ |
| **假正例率 (FPR / 误报率)** | 40.08% | 40.08% | $FP / (FP + TN)$ |
| **精确率 (Precision)** | 72.71% | 72.71% | $TP / (TP + FP)$ |
| **F1-Score** | 0.842 | 0.842 | 综合衡量准确与召回 |
| **OWASP 综合得分 (Youden's J)** | **+59.92%** | **+59.92%** | $(TPR - FPR) \times 100\%$ |

## 2. 11 项脆弱性分类详细分布

| 分类标识 | 对应 CWE | 用例总数 | TP (检出) | FP (误报) | FN (漏报) | TPR (召回率) | FPR (误报率) | OWASP 得分 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **cmdi** (Command Injection) | CWE-78 | 251 | 126 | 64 | 0 | 100.00% | 51.20% | **+48.80%** |
| **crypto** (Weak Cryptography) | CWE-327 | 246 | 130 | 27 | 0 | 100.00% | 23.28% | **+76.72%** |
| **hash** (Weak Hash Algorithm) | CWE-328 | 236 | 129 | 33 | 0 | 100.00% | 30.84% | **+69.16%** |
| **ldapi** (LDAP Injection) | CWE-90 | 59 | 27 | 13 | 0 | 100.00% | 40.62% | **+59.38%** |
| **pathtraver** (Path Traversal) | CWE-22 | 268 | 133 | 66 | 0 | 100.00% | 48.89% | **+51.11%** |
| **securecookie** (Insecure Cookie) | CWE-614 | 67 | 36 | 0 | 0 | 100.00% | 0.00% | **+100.00%** |
| **sqli** (SQL Injection) | CWE-89 | 504 | 272 | 207 | 0 | 100.00% | 89.22% | **+10.78%** |
| **trustbound** (Trust Boundary) | CWE-501 | 126 | 83 | 24 | 0 | 100.00% | 55.81% | **+44.19%** |
| **weakrand** (Weak Randomness) | CWE-330 | 493 | 218 | 0 | 0 | 100.00% | 0.00% | **+100.00%** |
| **xpathi** (XPath Injection) | CWE-643 | 35 | 15 | 7 | 0 | 100.00% | 35.00% | **+65.00%** |
| **xss** (Cross-Site Scripting) | CWE-79 | 455 | 246 | 90 | 0 | 100.00% | 43.06% | **+56.94%** |

> 注：OWASP Score 基准得分为零代表算法效果等同于掷硬币随机猜测，得分大于 40% 为业界优秀白盒工具水平，大于 60% 达到高精密度级别。
