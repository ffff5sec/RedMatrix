# RedMatrix

红队资产测绘平台 —— Go 模块化单体后端 + Vue 3 前端 + 分布式扫描节点 + 三层插件架构。

把根域名喂进来，自动展开成「子域名 → IP/端口 → URL → 指纹 → 证书 → 漏洞」资产图谱；新增 / 消失 / 即将过期事件实时推到 webhook / 邮件。

## 当前状态

MVP v1.0（截至 2026-05）功能基线：

- **多账户多项目 RBAC**：SuperAdmin / ProjectAdmin / TenantAuditor / PlatformAuditor 四角色；BOLA 防护 + 项目级 ProjectMember + 节点白名单
- **资产发现**：subfinder + amass + ksubdomain + crtsh + fofa + hunter + quake（子域名）/ nmap + rustscan + fingerprintx（端口）/ gospider + wayback + katana（URL）/ httpx（指纹）/ tlsx（证书）
- **资产变更事件流**：5 类（asset_new_subdomain/port/service + asset_disappeared + cert_expiring_soon）端到端 → 时间线 UI → webhook / 邮件
- **三层插件架构**：L1 原生适配器（4 个）+ L2 二进制包装器（多个）；L3 YAML POC 引擎 Phase 2
- **扫描套件 chaining**：subfinder → nmap → nuclei 一键展开
- **扫描结果导出**：CSV / JSON / Excel 三种格式
- **漏洞工单**：dedup_key 去重 + 5 状态机 + 看板 + 评论 + 指派
- **审计 hash 链**：append-only trigger + per-tenant 单链 + UI 校验
- **mTLS 节点接入**：自签 PKI CA + 一次性 RegistrationToken + ed25519 客户端证书
- **插件包分发**：.rpkg + ed25519 签名 + Agent 拉取 + 原子安装

## 快速开始

### 本地 dev

```bash
make dev-up               # 起 PG / Redis / ES / MinIO
make migrate              # 跑 schema migration
go run ./cmd/server       # 启 server（首启自动 bootstrap admin）
cd web && pnpm install && pnpm dev   # 起前端
```

浏览器打开 `http://localhost:5173/`。bootstrap admin 凭据见 `dev/.env.dev`。

### 生产部署

见 [`deploy/README.md`](deploy/README.md) —— Server 全栈 + 单独 Scan Node 两份 docker-compose + .env 模板 + 6 节文档（首启 / 节点接入 / TLS 反代 / 备份 / 升级 / FAQ）。

## 文档

- **[deploy/README.md](deploy/README.md)** —— 部署与首启
- **[OPERATIONS.md](OPERATIONS.md)** —— 日常运维（监控 / 备份 / 故障排查 / 用户与节点管理 / 密钥轮换）
- **[PLUGIN_DEV.md](PLUGIN_DEV.md)** —— 插件开发（L1 原生适配器 / L2 二进制包装器 / L3 YAML POC / 打包 / 签名 / 上传）

## 架构

```
┌──────────────────────────┐
│  Web UI (Vue 3 + Vite)   │   ConnectRPC over HTTP/1+2
├──────────────────────────┤
│  Server (Go 1.25)        │   PG + ES + Redis + MinIO
│  - identity / tenancy    │
│  - scan / asset / finding│
│  - notify / audit        │
│  - pluginpkg / export    │
└────────────┬─────────────┘
             │ mTLS over gRPC
   ┌─────────┴──────────┐
   │  Scan Node (agent) │   L1/L2 plugins fork-exec 真扫描器
   │  - puller          │   nmap / subfinder / nuclei / tlsx / ...
   │  - executor        │
   └────────────────────┘
```

完整设计文档在 `docs/`（本地）—— HLD / LLD / SPEC / PRODUCT / DESIGN / UX，详见 `docs/LLD/README.md`。

## 许可

TBD —— 暂为内部研发版本。

## 贡献

PR 流程详见各模块的 LLD 文档；提交前跑 `make test && make lint`。
