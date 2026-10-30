# DevSecOps 统一安全编排平台

本项目整合 SAST 与 DAST 扫描能力，并采用以下职责边界：

- `devsecops-cli`：CI/CD 薄客户端，只负责提交、等待和门禁查询。
- `devsecops-server`：统一 API、资产与任务管理、结果聚合和质量门禁。
- `devsecops-worker-sast`：CodeQL 扫描执行节点。
- `devsecops-worker-dast`：端口发现、指纹识别与 Neutron PoC 验证节点。

两个 Worker 都不连接 PostgreSQL。SAST Worker 通过受 Token 保护的回调接口回传日志、
SARIF 和规范化漏洞；DAST Worker 通过 Redis 回传状态、资产与漏洞。

Agent/AI 分析和 SCA 扫描目前不属于当前实现范围，代码中不保留未使用的占位模型。

## 架构

```text
CI/CD
  |
  | POST /api/v1/scans
  v
devsecops-server
  |-- Asynq ----------------------> devsecops-worker-sast
  |<-- HTTPS callback ------------ devsecops-worker-sast
  |-- Redis Streams --------------> devsecops-worker-dast
  |
  |-- PostgreSQL                      SAST 任务与漏洞
  `-- Redis                           DAST 任务状态、资产与发现

CI/CD
  |
  | GET /api/v1/scans/{scan_id}/gate
  v
devsecops-server
```

统一扫描 ID 使用 `<type>:<id>` 格式：

```text
sast:42
dast:dast-1780000000000000000
```

## 目录

```text
cmd/
├── cli/                统一轻量 CLI
├── server/             聚合 Server
├── worker-sast/        SAST Worker
└── worker-dast/        DAST Worker

internal/
├── pipeline/           统一扫描提交、状态和门禁
├── router/             HTTP 路由
├── sast/               CodeQL、SARIF、SAST 任务
├── dast/               DAST 引擎、调度、POC 与结果
└── model/              公共持久化基础类型

web/                    Vue 3 管理界面
configs/example.yaml    WSL/Linux 示例配置
pocs/                   版本化 DAST PoC 部署目录
```

## 构建

推荐使用静态链接，便于在精简 CI 容器中直接运行：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o devsecops-cli ./cmd/cli
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o devsecops-server ./cmd/server
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o devsecops-worker-sast ./cmd/worker-sast
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o devsecops-worker-dast ./cmd/worker-dast
```

运行全部 Go 检查：

```bash
go test ./...
go vet ./...
go mod tidy -diff
```

## 启动

先启动 PostgreSQL 和 Redis，再分别启动服务：

```bash
./devsecops-server --config configs/example.yaml
./devsecops-worker-sast --config configs/example.yaml
./devsecops-worker-dast --config configs/example.yaml
```

CodeQL 路径和查询库路径必须按本机环境修改。示例配置使用 Linux 路径语义，不再依赖 Windows 盘符。

Server 与 `worker-sast` 必须配置相同的 `worker.token`。Worker 通过
`worker.callback_url` 回传任务日志、SARIF 和规范化漏洞结果；生产环境应使用
HTTPS 或受控内网，并替换示例 Token。

PoC 不再由 Server 管理，也不依赖对象存储。`worker-dast` 从
`dast.poc_dir` 读取版本化的 `poc_index.json` 和对应 YAML 规则；部署时应将
PoC 目录挂载到该路径，或将规则打包进 Worker 镜像。目录或索引缺失时 Worker
会拒绝启动，避免在无规则状态下产生误判通过。

## 统一扫描 API

### 提交 SAST

```http
POST /api/v1/scans
Content-Type: application/json

{
  "type": "sast",
  "repo_id": 1,
  "branch": "main",
  "language": "go",
  "rule_profile": "baseline",
  "rules": ["cwe-078", "cwe-089"]
}
```

### 提交 DAST

```http
POST /api/v1/scans
Content-Type: application/json

{
  "type": "dast",
  "task_name": "staging-api",
  "target": "https://staging.example.com",
  "ports": "80,443,8080"
}
```

### 查询状态

```http
GET /api/v1/scans/sast:42
GET /api/v1/scans/dast:task-id
```

### 查询质量门禁

```http
GET /api/v1/scans/sast:42/gate?fail_on=HIGH
GET /api/v1/scans/dast:task-id/gate?fail_on=CRITICAL
```

门禁由 Server 统一计算。客户端只根据 `passed` 映射退出码，不在本地重复判断严重级别。

支持的阈值：

```text
CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE
```

## CI/CD 使用

### 分步执行

```bash
SCAN_ID=$(
  ./devsecops-cli scan submit \
    --server http://devsecops.internal:22211 \
    --type sast \
    --repo-id 1 \
    --language go \
    --branch main | sed -n 's/^scan_id=\([^ ]*\).*/\1/p'
)

./devsecops-cli scan wait --server http://devsecops.internal:22211 --scan-id "$SCAN_ID"
./devsecops-cli scan gate --server http://devsecops.internal:22211 --scan-id "$SCAN_ID" --fail-on HIGH
```

### 一步完成

```bash
./devsecops-cli scan run \
  --server http://devsecops.internal:22211 \
  --type sast \
  --repo-id 1 \
  --language go \
  --branch main \
  --fail-on HIGH
```

DAST：

```bash
./devsecops-cli scan run \
  --server http://devsecops.internal:22211 \
  --type dast \
  --target https://staging.example.com \
  --ports 80,443,8080 \
  --fail-on HIGH
```

退出码：

- `0`：扫描成功且门禁通过。
- `1`：扫描失败或门禁阻断。
- `2`：参数、网络或平台错误。

## 前端开发

```bash
cd web
npm ci
npm run build
```

项目统一使用 npm 和 `package-lock.json`。
