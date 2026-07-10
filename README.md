# DevSecOps 

本平台是一个集成了 **SAST** 与 **DAST** 的 DevSecOps 平台。
## 一、环境部署指南

### 1. 基础依赖项

- **Go (v1.25.4+)**：后端 Gin 框架编译与运行。
- **Node.js (v18+)**：前端 Vite-Vue 编译与构建。
- **PostgreSQL (v12+)**：存储代码仓库、扫描任务、漏洞报告及 PoC 模板等核心数据。
- **Redis (v6+)**：作为 Asynq 队列（SAST 扫描任务）与 DAST 动态扫描队列的支撑。
- **CodeQL CLI (v2.25.6+)**：静态应用扫描的核心执行引擎，需预先下载配置好目录。
- **CodeQL Queries**：CodeQL 官方库（查询规则文件），扫描时需要加载。

### 2. 依赖环境 Docker 部署命令

```bash
# 作用：启动 PostgreSQL 数据库服务 (端口: 5432)
docker run --name postgres-devsecops -e POSTGRES_USER=codeql -e POSTGRES_PASSWORD=codeql123 -e POSTGRES_DB=codeql_platform -p 5432:5432 -d postgres:14

# 作用：启动 Redis 缓存与队列服务 (端口: 6379)
docker run --name redis-devsecops -p 6379:6379 -d redis:7

# 作用：启动 MinIO 对象存储服务 (API端口: 9000, 控制台端口: 9001)
docker run --name minio-devsecops -p 9000:9000 -p 9001:9001 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin123 -d minio/minio server /data --console-address ":9001"
```

### 3. 服务配置

在 `configs/config.local.yaml` 文件中根据本地环境配置数据库、Redis 与 CodeQL 路径：

- `database`: 修改 host、port、user、password 及 dbname 等。
- `redis`: 修改连接地址及 db 索引。
- `minio`: 修改 endpoint、access_key 及 secret_key 等。
- `scanner`: 配置 `codeql_path` 指向 CodeQL CLI 对应可执行文件路径，配置 `codeql_queries` 指向规则库所在根目录。

---

## 二、快速启动指南

```bash
go mod tidy 
cd web && npm run build
go build -o devsecops main.go
```
---

## 三、核心 API 详解

### 1. SAST 代码仓库模块 (SAST Repository)

- **创建/登记代码仓库**
  - **接口**：`POST /api/v1/repos`
  - **Payload 示例**：
    ```json
    {
      "name": "test-repo",
      "url": "https://github.com/example/test-repo.git",
      "branch": "main",
      "language": "go",
      "auth_type": "none",
      "auth_secret": "",
      "auto_scan_enabled": false,
      "scan_config": {
        "query_suite": "security-extended",
        "exclude_paths": ["/vendor", "/test"],
        "build_command": ""
      }
    }
    ```
- **获取仓库列表**
  - **接口**：`GET /api/v1/repos/list`
  - **参数**：`page` (默认 1), `per_page` (默认 20)
- **更新仓库配置**
  - **接口**：`POST /api/v1/repos/update/:id`
- **批量删除仓库**
  - **接口**：`POST /api/v1/repos/batch-delete`
  - **Payload 示例**：`{"ids": [1, 2, 3]}`

### 2. SAST 静态扫描模块 (SAST Scan)

- **手动创建扫描任务**
  - **接口**：`POST /api/v1/scan/tasks`
  - **Payload 示例**：
    ```json
    {
      "repo_id": 1,
      "branch": "main",
      "language": "go",
      "query_suite": "baseline",
      "rule_profile": "",
      "rules": []
    }
    ```
- **查询扫描任务列表**
  - **接口**：`GET /api/v1/scan/ListTasks`
  - **参数**：`repo_id` (可选筛选), `status` (任务状态筛选)
- **查询漏洞列表**
  - **接口**：`GET /api/v1/scan/vulnerabilities`
  - **参数**：`task_id` (必填)
- **查看任务执行日志**
  - **接口**：`GET /api/v1/scan/tasks/:id/logs`
- **获取扫描 SARIF 报告摘要**
  - **接口**：`GET /api/v1/scan/tasks/:id/sarif/summary`
- **下载原始 SARIF 文件**
  - **接口**：`GET /api/v1/scan/tasks/:id/sarif`

### 3. DAST 动态扫描模块 (DAST Scan)

- **创建 DAST 扫描任务**
  - **接口**：`POST /api/v1/dast/scan/tasks`
  - **Payload 示例**：
    ```json
    {
      "task_id": "dast-job-1001",
      "ips": "192.168.1.1/24",
      "ports": "80,443,8080"
    }
    ```
- **查询 DAST 任务列表**
  - **接口**：`GET /api/v1/dast/scan/tasks`
- **查询 DAST 任务进度状态**
  - **接口**：`GET /api/v1/dast/scan/tasks/:id/status`
- **获取 DAST 扫描发现的漏洞**
  - **接口**：`GET /api/v1/dast/scan/tasks/:id/results`

### 4. DAST PoC 模板模块 (DAST PoC)

- **创建 PoC 模板**
  - **接口**：`POST /api/v1/dast/pocs`
  - **Payload 示例**：
    ```json
    {
      "name": "cve-2023-xxxx",
      "description": "CVE-2023-xxxx 漏洞检测 PoC",
      "content": "id: cve-2023-xxxx\ninfo:\n  name: Test PoC\n  severity: high\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/status\""
    }
    ```
- **获取 PoC 模板列表**
  - **接口**：`GET /api/v1/dast/pocs`
- **修改 PoC 模板**
  - **接口**：`POST /api/v1/dast/pocs/update/:id`
- **删除 PoC 模板**
  - **接口**：`POST /api/v1/dast/pocs/delete/:id`
