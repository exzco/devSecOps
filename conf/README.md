

DevSecOps 平台在 Linux 服务器生产环境部署的 Systemd 服务配置单元与应用配置模板。

## 文件列表

* `devsecops-server.service`: DevSecOps 中央管理服务（Web 控制台与统一 API）
* `devsecops-worker-sast.service`: CodeQL 静态代码分析 Worker
* `devsecops-worker-dast.service`: 动态漏洞扫描与 Neutron PoC 验证 Worker
* `config.yaml`: 生产环境配置模板（数据库、Redis、CodeQL 路径及回调设置）

---

## 1. 基础环境配置 (Redis, PostgreSQL, CodeQL)

### 1.1 PostgreSQL 容器部署与配置

通过 Docker 部署 PostgreSQL 15 容器，数据持久化存储至宿主机 `/opt/devsecops/data/postgres`：

```bash
mkdir -p /opt/devsecops/data/postgres

docker run -d --name devsecops-pg \
  --restart always \
  -p 5432:5432 \
  -e POSTGRES_USER=codeql \
  -e POSTGRES_PASSWORD=codeql123 \
  -e POSTGRES_DB=codeql_platform \
  -v /opt/devsecops/data/postgres:/var/lib/postgresql/data \
  postgres:15-alpine
```

* 数据库主机：`127.0.0.1`
* 端口：`5432`
* 用户名：`codeql`
* 密码：`codeql123`
* 数据库名称：`codeql_platform`

> 若需要将既有环境的数据导入新环境：
> ```bash
> # 本机导出并直接通过管道导入远程
> docker exec devsecops-pg pg_dump -U codeql codeql_platform | ssh root@<服务器IP> "docker exec -i devsecops-pg psql -U codeql -d codeql_platform"
> ```

---

### 1.2 Redis 容器部署与配置

通过 Docker 部署 Redis 容器，启用 AOF 持久化：

```bash
mkdir -p /opt/devsecops/data/redis

docker run -d --name devsecops-redis \
  --restart always \
  -p 6379:6379 \
  -v /opt/devsecops/data/redis:/data \
  redis:alpine redis-server --appendonly yes
```

* Redis 主机：`127.0.0.1`
* 端口：`6379`
* DB 编号：`10`（在 `config.yaml` 中指定）

---

### 1.3 CodeQL 运行环境与规则包配置

CodeQL CLI 及其规则包部署于 `/opt/devsecops/codeql` 目录：

```bash
wget https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz -O /tmp/codeql-bundle-linux64.tar.gz

mkdir -p /opt/devsecops
tar -zxvf /tmp/codeql-bundle-linux64.tar.gz -C /opt/devsecops/
rm -f /tmp/codeql-bundle-linux64.tar.gz

/opt/devsecops/codeql/codeql version
```

`config.yaml` 中对应映射配置：
```yaml
scanner:
  codeql_path: "/opt/devsecops/codeql/codeql"
  codeql_queries: "/opt/devsecops/codeql/qlpacks"
  work_dir: "/opt/devsecops/data/sast"
```

---

## 2. 服务安装与激活

将本目录下的 `.service` 文件复制到系统的 `/etc/systemd/system/` 目录下，并设置开机自启：

```bash
cp conf/*.service /etc/systemd/system/
systemctl daemon-reload

systemctl enable devsecops-server devsecops-worker-sast devsecops-worker-dast
systemctl start devsecops-server devsecops-worker-sast devsecops-worker-dast
```

---

## 3. 服务运维常用指令（在 cvps1 上执行）

### 3.1 查看服务状态：
```bash
systemctl status devsecops-server devsecops-worker-sast devsecops-worker-dast
```

### 3.2 查看实时日志：
```bash
# 服务端日志
journalctl -u devsecops-server -f

# SAST Worker 扫描日志
journalctl -u devsecops-worker-sast -f

# DAST Worker 渗透日志
journalctl -u devsecops-worker-dast -f
```

### 3.3 重启全套服务：
```bash
systemctl restart devsecops-server devsecops-worker-sast devsecops-worker-dast
```
