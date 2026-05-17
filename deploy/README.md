# RedMatrix 生产部署

本目录提供 `docker compose` 部署 RedMatrix 的样板配置。

- `docker-compose.prod.yml` — Server 全栈（PG + Redis + ES + MinIO + server）
- `docker-compose.node.yml` — 单独 Scan Node（agent）
- `.env.prod.example` — Server 栈环境变量模板
- `.env.node.example` — Node 环境变量模板

是**样板，非 turn-key**：生产前需按贵团队 SRE 标准改造（密钥来源、TLS 反代、备份、监控）。

---

## 1. Server 栈首启

### 1.1 准备密钥

需要 4 个 base64 32-byte 密钥（互异）：

```bash
for v in JWT_SECRET ENCRYPTION_KEY AUDIT_HMAC_KEY BACKUP_KEY; do
  echo "$v=$(openssl rand -base64 32)"
done
```

任意一个泄漏：JWT_SECRET 漏 → 全用户 session 重签；ENCRYPTION_KEY 漏 → PG 中加密字段全暴露；AUDIT_HMAC_KEY 漏 → 审计链可伪造；BACKUP_KEY 漏 → 备份归档可解密。**生产建议**：从 Vault / SSM / GCP Secret Manager 注入而非明文落盘。

数据库 / Redis / MinIO 密码用强随机：

```bash
for v in POSTGRES_ADMIN_PASSWORD REDMATRIX_APP_PASSWORD REDMATRIX_MAINT_PASSWORD REDIS_PASSWORD MINIO_ROOT_PASSWORD; do
  echo "$v=$(openssl rand -base64 24 | tr -d /+= | head -c 24)"
done
```

### 1.2 配置

```bash
cp deploy/.env.prod.example deploy/.env.prod
# 把上一步生成的密钥贴进去；改 PUBLIC_DOMAIN / PUBLIC_GRPC_ADDR / MINIO_PUBLIC_ENDPOINT
chmod 600 deploy/.env.prod
```

`PUBLIC_GRPC_ADDR` 必须是公网可达（agent 在外网时尤其）；`MINIO_PUBLIC_ENDPOINT` 是 presigned URL 的 host，浏览器 / agent 都要能解析到。

### 1.3 构建 + 启动

```bash
cd <repo-root>
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod build server
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod up -d
docker compose -f deploy/docker-compose.prod.yml logs -f server
```

首启 server 会自动：跑 goose migration → 建 9 个 MinIO bucket → 创建 ed25519 PKI CA → bootstrap admin 账号。

### 1.4 登录 + 改密

浏览器访问 `https://<PUBLIC_DOMAIN>/`（若未配 TLS 反代则 `http://<host>:8080/`），用 `ADMIN_BOOTSTRAP_USERNAME` + `ADMIN_BOOTSTRAP_PASSWORD` 登录。前端会强制弹出修改密码 Modal（PR-S60），改完用新密码重登。改密后 `ADMIN_BOOTSTRAP_PASSWORD` 即作废。

---

## 2. 节点（Scan Node）接入

### 2.1 在 server UI 生成 RegistrationToken

SA 角色登录 → 「节点管理」→ 「生成注册 token」→ 拷贝 `rmnode_xxx`（一次性，10 分钟内有效）。

### 2.2 在 agent 主机上部署

```bash
# 把仓库或至少 deploy/ + cmd/node/ 拷到 agent 主机；或直接用预构建的 redmatrix-node 镜像
cp deploy/.env.node.example deploy/.env.node
# 填 REDMATRIX_NODE_TOKEN / REDMATRIX_NODE_NAME / REDMATRIX_SERVER_URL / REDMATRIX_NODE_AGENT_URL
chmod 600 deploy/.env.node

# 放扫描器二进制（agent 内置 L1 + mock；L2 需外置）
sudo mkdir -p /opt/redmatrix/plugins
# 例：把 nmap / subfinder / httpx / nuclei / tlsx / ksubdomain / fingerprintx / gospider 等拷进去

docker compose -f deploy/docker-compose.node.yml --env-file deploy/.env.node build node
docker compose -f deploy/docker-compose.node.yml --env-file deploy/.env.node up -d
docker compose -f deploy/docker-compose.node.yml logs -f node
```

成功日志关键字：`node registered ok`、`mtls heartbeat ok`。失败常见原因：

- token 过期 / 已用 → server UI 重新生成
- `REDMATRIX_NODE_AGENT_URL` 不可达 → 检查防火墙 / DNS
- mTLS SAN mismatch → server URL 用 IP 时不需要 SAN override；用域名时确保 cert 含该域名

接入后 agent 自动 leaf cert 持久在 `node-data` volume，重启不需重新 redeem token。

---

## 3. TLS 反代（强烈建议）

样板 compose 把 8080 / 9090 直接暴露。生产应在 server 前面加 Caddy / Nginx / Traefik 终结 TLS。`docker-compose.prod.yml` 末尾有 `caddy` 服务的注释模板。

最小 Caddyfile（自动 ACME）：

```caddy
redmatrix.example.com {
  reverse_proxy server:8080
}
```

mTLS 控制面（9090）保持直暴露，不走反代 —— 因为 server 自己用 ed25519 PKI 签节点客户端证书 + 校验，反代会破坏 mTLS 链。

---

## 4. 备份建议

| 数据 | 频率 | 命令 |
|---|---|---|
| PostgreSQL | 每天 | `docker compose exec pg pg_dump -U postgres redmatrix \| gzip > pg-$(date +%F).sql.gz` |
| Elasticsearch | 每周 | snapshot API + MinIO repository（`redmatrix-es-snapshots` bucket） |
| MinIO | 持续 | `mc mirror local/redmatrix-* s3-backup/redmatrix-mirror/` |
| 4 个秘钥 | 一次写入 secret manager | 别人手上必须备份；丢了的话备份归档也解不开 |
| PKI CA（server-data volume） | 一次性归档 | `tar czf pki.tar.gz /data/pki`；节点客户端证书续期靠 CA |

---

## 5. 升级

```bash
git pull
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod build server
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod up -d server
# RM_AUTO_MIGRATE=true 让 server 启动期自动跑新的 goose migration
```

回滚：保留旧镜像 tag，把 `SERVER_VERSION` 改回旧值再 `up -d server`。schema migration 是单向的，回滚前请确认旧版本 server 能接受新 schema（一般小版本兼容，大版本看 release note）。

---

## 6. 常见问题

**Q: server 启动报 BOOTSTRAP_CRYPTO_INVALID？**
A: 4 个密钥不是合法 base64 / 不是 32 字节 / 互相相同。用 `openssl rand -base64 32` 重生。

**Q: 节点接入后立刻 disconnected？**
A: 看 server 日志 + agent 日志。常见：mTLS SAN mismatch（server URL 用域名但 cert 是 IP）；防火墙拦 9090 出站；token 已 redeem 过。

**Q: 浏览器登录提示「captcha 失败」？**
A: captcha 走 Redis 缓存。检查 Redis 服务健康 + 时钟同步（容器宿主 NTP）。

**Q: MinIO presigned URL 浏览器打不开（403/connection refused）？**
A: `MINIO_PUBLIC_ENDPOINT` 必须浏览器侧可达。同 VPC 部署且没暴露公网 → 加 Caddy 反代 minio 或换 hostNetwork。

更多见 docs/LLD/40-deployment-detail.md（仓内部文档，docs/ 不入 git）。
