# RedMatrix 运维手册

针对**已部署**的 RedMatrix 实例做日常维护。部署初次启动看 [`deploy/README.md`](deploy/README.md)。

## 目录

1. [架构与组件](#1-架构与组件)
2. [监控](#2-监控)
3. [日志](#3-日志)
4. [用户与角色](#4-用户与角色)
5. [节点管理](#5-节点管理)
6. [备份与恢复](#6-备份与恢复)
7. [密钥轮换](#7-密钥轮换)
8. [升级](#8-升级)
9. [故障排查](#9-故障排查)
10. [审计日志](#10-审计日志)

---

## 1. 架构与组件

| 组件 | 端口 | 作用 | 关键状态 |
|---|---|---|---|
| server | 8080 (HTTP) / 9090 (mTLS) | Web + ConnectRPC + 节点控制面 | `/health` + `/ready` + `/metrics` |
| pg | 5432 | 主数据存储 | `redmatrix_app` / `redmatrix_maintenance` 角色 |
| redis | 6379 | session / captcha / scheduler lock | `--requirepass` |
| es | 9200 | scan_results 全文检索 | single-node + `xpack.security.enabled=false`（生产应启） |
| minio | 9000 / 9001 (console) | artifact / report / screenshot / 备份 | 9 个 bucket |
| node (agent) | — | 拉任务 + fork 扫描器 + 上报 | leaf cert in `/data` volume |

## 2. 监控

### 2.1 健康检查

| 端点 | 含义 |
|---|---|
| `GET /health` | 进程存活；返 200 即 server 进程在 |
| `GET /ready` | 依赖就绪；PG / ES / Redis / MinIO 任一不通返 503 |
| `GET /metrics` | Prometheus exposition；scrape interval 建议 15s |

### 2.2 关键指标

5 个核心业务 metric（namespace `redmatrix`）：

| 指标 | Help |
|---|---|
| `redmatrix_scan_tasks_created_total{kind}` | 已创建 scan_tasks 累计；按 kind（port_scan/subdomain/...）拆 |
| `redmatrix_scan_tasks_terminal_total{status}` | task 进入终态累计；按 completed/failed/canceled 拆 |
| `redmatrix_scan_scheduler_triggers_total` | cron 触发回调累计；与 tasks_created 对比可算 cron 驱动比例 |
| `redmatrix_scan_sweeper_swept_total` | sweeper 把 stale assignment 标 failed 的累计；持续上涨 = 节点不健康 |
| `redmatrix_scan_results_inserted_total` | service.ReportResults 写 PG 成功的 result 行累计 |

### 2.3 推荐告警

| 名称 | PromQL | 含义 |
|---|---|---|
| 节点失联 | `increase(redmatrix_scan_sweeper_swept_total[5m]) > 5` | 5 分钟内 >5 个 assignment 被 sweep，说明节点 lost |
| 任务失败率高 | `rate(redmatrix_scan_tasks_terminal_total{status="failed"}[15m]) / rate(redmatrix_scan_tasks_terminal_total[15m]) > 0.2` | 失败比例 >20% |
| Server 进程死 | `up{job="redmatrix-server"} == 0` 5m | 抓不到 /metrics |
| Notify sweeper 堆积 | 自定义 - 查 `notification_deliveries` WHERE status='pending' AND scheduled_at < now() - 5m | webhook / 邮件下行链路异常 |

## 3. 日志

容器日志：

```bash
docker compose -f deploy/docker-compose.prod.yml logs -f server
docker compose -f deploy/docker-compose.node.yml logs -f node
```

server 默认 JSON 格式（`LOG_FORMAT=json`，`LOG_LEVEL=info`）。生产建议接到 Loki / Elasticsearch / CloudWatch 等聚合后端。

排错时临时调 debug：

```bash
docker compose ... up -d --no-deps -e LOG_LEVEL=debug server
```

## 4. 用户与角色

四角色权限矩阵（HLD §4.3 强制；PR-S40 收紧）：

| 操作 | SA | PA | TA | PlatformAuditor |
|---|---|---|---|---|
| 跨租户查 | ✅ | ❌ | ❌ | ✅ |
| 本租户写 | ✅ | ✅ 限项目 | ❌ | ❌ |
| 项目 CRUD | ✅ | ❌ | ❌ | ❌ |
| 节点接入 / 注销 | ✅ | ❌ | ❌ | ❌ |
| 插件包上传 | ✅ | ❌ | ❌ | ❌ |
| 扫描任务创建 / 取消 | ✅ | ✅ 限项目 | ❌ | ❌ |
| 漏洞工单转移 / 评论 | ✅ | ✅ 限项目 | ❌ | ❌ |
| 审计日志查 | ✅ | 本租户 | 本租户 | ✅ |
| 导出资产 / 漏洞 | ✅ | ✅ 限项目 | ✅ 限租户 | ✅ |

### 4.1 创建用户

SA UI → 用户管理 → 「新建用户」：选 role + tenant（PA 还要绑 ProjectMember）。返回的临时密码用 bootstrap 同款流程，首登强制改密。

### 4.2 强制下线

SA UI → 用户管理 → 用户行 → 「强制全部登出」。后端 bump 该用户 `token_version`，所有已签 JWT 立即失效。

### 4.3 禁用账号

SA UI → 「禁用」（非删除）。审计 `user_disabled`；重启用走「启用」按钮。删除走 SA cli 工具或直接 PG `UPDATE users SET deleted_at = now()`（极少需要，审计链不会断）。

## 5. 节点管理

### 5.1 接入新节点

详见 [`deploy/README.md` §2 节点接入](deploy/README.md#2-节点scan-node接入)。要点：

- 一次性 RegistrationToken（`rmnode_xxx`）从 SA UI 生成，10 分钟内有效
- 接入成功后 leaf cert 持久在 agent 主机的 `node-data` volume
- 同 tenant 下节点名唯一

### 5.2 节点白名单（AllowedNodes）

SA 给 tenant 设 AllowedNodes 后，该 tenant 的 scan task 只会派到列表内节点。无白名单 = 全节点池。

UI：「租户管理」→ 选 tenant → 「分配节点」。

### 5.3 节点离线 / 注销

- 暂离线：agent 进程 down，无需 server 操作。重启 agent 用旧 leaf cert 自动 reconnect。
- 永久注销：SA UI → 「节点管理」→ 「注销」。后端把节点标 `inactive`，所有 in-flight assignment 回收。

### 5.4 节点上的插件二进制

L2 plugin（nmap / subfinder / nuclei / tlsx / ...）是外部二进制，agent fork-exec 调用。把它们放到 `PLUGIN_HOST_DIR`（默认 `/opt/redmatrix/plugins`），compose mount 进容器自动加入 PATH。

新版本 plugin 二进制热升级：替换文件即可，agent 下次 fork 自动用新版。要等正在运行的 task 完成才生效。

## 6. 备份与恢复

### 6.1 备份范围

| 数据 | 频率 | 命令 |
|---|---|---|
| PostgreSQL | 每天 | `docker compose exec pg pg_dump -U postgres redmatrix \| gzip > pg-$(date +%F).sql.gz` |
| Elasticsearch | 每周 | snapshot API + MinIO repository（`redmatrix-es-snapshots` bucket） |
| MinIO | 持续 mirror | `mc mirror local/redmatrix-* s3-backup/redmatrix-mirror/` |
| 4 个秘钥 | 一次性 secret manager | 单独归档；丢了备份归档也解不开 |
| PKI CA（`server-data` volume） | 一次性归档 | `tar czf pki.tar.gz` 拷宿主机 `/var/lib/docker/volumes/redmatrix-prod_server-data/_data/pki` |

### 6.2 恢复

灾恢核心是**密钥 + PG**。这两个全了，ES / MinIO 都能从备份恢复或重建。

恢复步骤：

1. 起新 stack：`docker compose ... up -d pg redis es minio`
2. 把 4 个秘钥 + 三个 PG 密码注回 `.env.prod`
3. `gunzip -c pg-YYYY-MM-DD.sql.gz | docker compose exec -T pg psql -U postgres redmatrix`
4. PKI 归档解到 server-data volume 对应路径
5. `docker compose ... up -d server`
6. （可选）从 ES snapshot 恢复历史 scan_results；不恢复 = 新任务从空 index 开始
7. 节点：旧 leaf cert 还在 agent 主机 → 直接重启 agent 重新接入

## 7. 密钥轮换

### 7.1 JWT_SECRET

风险：泄露后攻击者可签任意用户的 token。
轮换步骤：

1. 生成新 secret：`openssl rand -base64 32`
2. 改 `.env.prod`
3. `docker compose ... up -d server`（重启）
4. 所有用户被踢登录页（旧 token 验签失败）

**注意**：JWT 没有平滑过渡机制；轮换 = 立即生效 + 全员重登。计划在维护窗口做。

### 7.2 ENCRYPTION_KEY

风险：泄露后 PG 中加密字段（如 API key、SMTP 密码）暴露。
轮换比 JWT 复杂：

1. 用 `cmd/server reencrypt --old-key <old> --new-key <new>` 工具（**未实现 — Phase 2 上**）批量重加密 PG 中字段
2. 在数据迁移完成前不能改 `.env.prod` 的 key，否则解密失败

目前如必须轮换：在维护窗口手动 `pg_dump` → 改 key → migrations 重跑 + secret 字段重置。

### 7.3 AUDIT_HMAC_KEY

风险：泄露后审计链可伪造（虽 append-only trigger 仍阻 INSERT 但 hash 可对齐假数据）。
轮换：单纯 server 重启即可生效新 HMAC；**历史审计行的 hash 用旧 key 计算，校验时按 prev_hash 链推下来仍连贯**。

### 7.4 BACKUP_KEY

风险：备份归档可解密。
轮换：单纯改 key 即可；新备份用新 key 加密，旧备份仍可用旧 key 解。建议轮换后用新 key 重生成最近一次完整备份。

### 7.5 PKI CA

风险：CA 私钥泄露 → 攻击者可签合法的 node leaf cert 假冒节点。
轮换：CA 重生 → 所有现有节点失效，必须重新走 RegistrationToken 接入。维护窗口操作：

1. 备份当前 CA：`tar czf pki-$(date +%F).tar.gz <server-data>/pki`
2. SA UI 「PKI 管理」→「重生 CA」（**Phase 2 加 UI 入口；当前直接 rm `/data/pki/*` + 重启 server**）
3. 所有节点 agent 重新 redeem RegistrationToken

## 8. 升级

```bash
git pull
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod build server
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env.prod up -d server
```

`RM_AUTO_MIGRATE=true` 让 server 启动期自动跑新的 goose migration。

**回滚**：保留旧镜像 tag，把 `SERVER_VERSION` 改回旧值再 `up -d server`。schema migration 是单向的，回滚前确认旧版本能接受新 schema（一般小版本兼容，大版本看 release note）。

Agent 升级（独立节奏）：

```bash
docker compose -f deploy/docker-compose.node.yml --env-file deploy/.env.node build node
docker compose -f deploy/docker-compose.node.yml --env-file deploy/.env.node up -d node
```

leaf cert 在 volume 持久，重启不需重新注册。

## 9. 故障排查

| 症状 | 可能原因 | 定位 |
|---|---|---|
| server 起不来 + `BOOTSTRAP_CRYPTO_INVALID` | 4 个密钥不是合法 base64 32 字节 / 互相相同 | `openssl rand -base64 32` 重生 |
| 节点接入后立即 disconnected | mTLS SAN mismatch / 防火墙拦 9090 / token 已 redeem | 看 server 日志 + agent 日志；token 重 issue |
| 浏览器登录提示 captcha 失败 | Redis 不通 / 时钟漂移 | `docker compose ps redis` + 看 server 日志 |
| MinIO presigned URL 403 / connection refused | `MINIO_PUBLIC_ENDPOINT` 浏览器侧不可达 | 加反代或换 hostNetwork |
| ES 写入间歇失败 | 单节点 JVM heap 不够 / disk watermark | `ES_JAVA_OPTS=-Xms4g -Xmx4g` + 看 `_cluster/health` |
| webhook / 邮件未送达 | sweeper 在重试 / SMTP 配置错 | 查 `notification_deliveries` WHERE status='pending' / 'failed'；看 server 日志 grep 'notify' |
| 任务一直 pending 不派发 | 无节点 online / 节点白名单空 / 节点不支持该 kind | SA UI 「节点管理」看在线状态；scan_task.kind 与节点 capability 比对 |
| 审计 UI「校验链」失败 | hash 链断（罕见，trigger 拦着）/ 校验时间窗超 1 万行 | 看 server 日志 grep 'audit verify'；缩小时间范围 |
| 资产事件未推送通知 | 订阅 event_kinds 未含资产事件 / 项目过滤不匹配 | UI 「通知订阅」检查 event_kinds 包含 `asset_new_*` / `asset_disappeared` / `cert_expiring_soon`；filter 含项目 |

## 10. 审计日志

### 10.1 完整性校验

UI → 「审计日志」→ 「校验整链」按钮：扫一段时间内的审计行，按 `prev_hash` 连续重算 `hash`，断点立即标红。

CLI（紧急排查）：

```sql
-- 选近 1000 行按 created_at ASC 排
SELECT id, prev_hash, hash FROM audit_logs
WHERE tenant_id = '<tenant-uuid>'
ORDER BY created_at ASC
LIMIT 1000;
-- 手工对比 prev_hash[N] == hash[N-1]
```

PG 触发器（`audit_logs_append_only`）禁止 UPDATE / DELETE。`current_user = 'redmatrix_app'` 仅 INSERT 权限；想清审计必须 `redmatrix_maintenance` 角色，且立即被审计本身记录（链上能看到自删事件，再删一次也是事件）。

### 10.2 关键 ActionKind

完整列表见 `internal/audit/domain/types.go`，常用：

| Action | 触发场景 |
|---|---|
| `login` / `logout` / `logout_all` | 登录、登出、强制全部登出 |
| `password_changed` / `password_reset` | 改密 / 重置 |
| `user_created` / `user_enabled` / `user_disabled` | 用户生命周期 |
| `task_create` / `task_cancel` / `task_delete` | 扫描任务 |
| `suite_run` | 扫描套件运行 |
| `finding_transition` / `finding_comment` / `finding_assign` | 漏洞工单 |
| `project_created` / `_archived` / `_deleted` | 项目生命周期 |
| `project_member_added` / `_removed` | PA 项目成员 |
| `notify_sub_created` / `_updated` / `_deleted` / `_tested` | 通知订阅 |
| `plugin_uploaded` | SA 上传 .rpkg |
| `assets_exported` / `findings_exported` | 数据导出 |

### 10.3 归档

每天 0:00 后台任务把超过 90 天的审计行打包 zstd → MinIO `redmatrix-audit-archive` bucket（用 `BACKUP_KEY` 加密）。归档前最后一行的 hash 同步写到 PG 归档元数据，让链不在归档边界断。

恢复归档查阅：

```bash
mc cp local/redmatrix-audit-archive/audit-2026-01-01.zst.enc /tmp/
# 用 BACKUP_KEY 解密 + zstd 解压
```

（解密工具：Phase 2 加 CLI）
