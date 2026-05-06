# 本地开发栈

一键起 PG + Redis + ES + MinIO + 自动建 9 bucket，配齐 env 直接跑 server。

仅供 demo / 开发；生产档遵循 LLD 40 部署细节。

## 快速开始

```bash
# 1. 起依赖（首启 ES 30s+ 才 healthy；MinIO bootstrap 自动建 9 bucket）
make dev-up

# 2. 跑 server（自动 source dev/.env.dev）
make dev-server
# 或：set -a && source dev/.env.dev && set +a && go run ./cmd/server

# 3. 起前端（另开 terminal）
cd web && pnpm install && pnpm dev
```

打开 http://localhost:5173，用户名 `admin`，密码 `DemoBootstrapPwd1!`（见 `.env.dev`）。

## 文件

| 文件 | 作用 |
|---|---|
| `docker-compose.yml` | PG / Redis / ES / MinIO + minio-bootstrap |
| `init-pg/01-roles.sql` | PG 首启执行：建 redmatrix_app / redmatrix_maintenance + 设密码 |
| `.env.dev` | server 启动所需全部 env（含 dev 密钥） |

## 端口

| 服务 | 主机端口 | 容器端口 |
|---|---|---|
| postgres | 5432 | 5432 |
| redis | 6379 | 6379 |
| elasticsearch | 9200 | 9200 |
| minio API | 9000 | 9000 |
| minio Console | 9001 | 9001 |
| redmatrix-server | 8080 | — |
| web (vite dev) | 5173 | — |

MinIO Console 默认账户 `minioadmin` / `minioadmin`。

## 重置

```bash
make dev-reset   # 停容器 + 删 volume；下次 dev-up 重新初始化角色 + bucket
```

## 注意

- `.env.dev` 用的是 dev-only 密钥 / 密码，**勿用于生产**。
- `RM_AUTO_MIGRATE=true` 让 server 启动时跑迁移；生产档由 CI 跑。
- 首启 server 会创建 `admin` SuperAdmin（用 `ADMIN_BOOTSTRAP_PASSWORD`）。
- 改了 `.env.dev` 后需要重启 server。
