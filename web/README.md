# RedMatrix · 前端演示

最小 SPA，演示 identity 模块全部 14 个 RPC。技术栈遵循 LLD 50（Vue 3 + Vite + TS +
ConnectRPC），**未引入** AntDV / Pinia / i18n —— 后续完整化时直接套上即可。

## 快速开始

### 1. 启动后端 server

按仓库根 README 配齐 env（`PG_DSN` / `REDIS_URL` 等），然后：

```bash
# 一次性建初始管理员密码（不设则启动时随机生成并 stdout）
export ADMIN_BOOTSTRAP_PASSWORD='YourStrongPwd1!'

go run ./cmd/server
```

server 监听 `:8080`；首启会自动创建 SuperAdmin（用户名 `admin`，邮箱
`admin@example.com`，密码同上 / 随机）。

### 2. 启动前端 dev server

```bash
cd web
pnpm install          # 首次
pnpm dev              # http://localhost:5173
```

Vite dev 把 `/redmatrix.identity.v1.IdentityService/*` 反向代理到 `:8080`，
避开浏览器 CORS。如后端端口不同：

```bash
RM_API_TARGET=http://localhost:9090 pnpm dev
```

### 3. 演示流

1. 浏览器开 `http://localhost:5173`
2. **登录**：用户名 `admin` + 第 1 步设的密码 + 输入图片验证码
3. **个人** Tab：看到 `must_change_password=true` → 点"改密"输入新密码
4. **API Keys** Tab：创建一个 key，密钥仅一次性显示
5. **用户管理** Tab（SA 可见）：创建 PROJECT_ADMIN，用回吐的临时密码再登录验证
   `must_change_password=true` 强制改密流程

## Proto 代码生成

更新 `api/proto/**` 后跑（仓库根目录）：

```bash
buf format -w
buf generate
```

会同时输出 Go（`gen/proto`）+ TS（`web/src/gen/proto`）。

## 目录

```
web/
├── package.json         # Vue 3 + Vite + TS + connect-web 仅这些核心依赖
├── vite.config.ts       # ConnectRPC 路径反向代理
├── tsconfig.json        # strict + noUncheckedIndexedAccess
├── index.html
└── src/
    ├── main.ts          # Vue 应用入口
    ├── App.vue          # 顶部 + 4 Tabs（Login / Profile / Keys / Users）
    ├── styles.css       # 无 UI 库；CSS 变量 + 系统字体栈
    ├── env.d.ts
    ├── api/
    │   └── transport.ts # ConnectTransport + Authorization 拦截器 + tv 哨兵
    ├── store/
    │   └── auth.ts      # JWT + principal 摘要（localStorage）
    ├── util/
    │   └── error.ts     # ConnectError → UI 字符串
    ├── views/
    │   ├── LoginPanel.vue       # GetCaptcha + Login
    │   ├── ProfilePanel.vue     # GetCurrentUser + ChangePassword + Logout / LogoutAllSessions
    │   ├── APIKeysPanel.vue     # ListAPIKeys + CreateAPIKey + RevokeAPIKey
    │   └── UsersPanel.vue       # ListUsers + CreateUser + Enable/Disable/ResetPassword/ForceLogout
    └── gen/proto/       # buf generate 产出（不入 git；构建前需先生成）
```

## 演示外的 TODO

- AntDV 接入（生产 UI）
- Pinia + 全局错误 Toast
- vue-router（按角色路由守卫）
- i18n（en / zh）
- E2E（playwright）

均见 LLD 50 §1.1。
