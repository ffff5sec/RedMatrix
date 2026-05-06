-- 创建 api_keys 表（LLD 10 §8）。
--
-- API Key 是脚本 / CI / SDK 调 ConnectRPC 的长令牌，与用户绑定（user.role 决定权限）。
-- 格式：rmk_<8 字符 prefix><40 字符 secret>，共 52 字符。
--
-- 字段：
--   id            UUID PK
--   tenant_id     UUID nullable（owner=SuperAdmin 时空）
--   user_id       UUID FK → users(id) ON DELETE CASCADE（用户删了 → key 全没）
--   name          用户给的友好名（如 "ci-bot"）
--   key_prefix    8 字符明文（base32 无歧义字母表）；UNIQUE 索引；用户可见
--   secret_hash   SHA-256(secret) hex（64 字符）
--                 — 不用 argon2id/bcrypt：30 字节随机熵 ≫ 任何爆破阈值；
--                 慢哈希在每次 RPC 都跑会成 DoS 放大器（攻击者塞假 key 烧 CPU）
--   scopes        JSONB 数组（如 ["scan:read", "asset:write"]）；MVP 暂不强制，
--                 仅持久存储，后续 PR 接 authz interceptor
--   expires_at    nullable = 永不过期
--   last_used_at  nullable，命中后 best-effort 异步刷（PR3-B）
--   revoked_at    nullable，soft revoke；revoked → 永久不可用
--   created_at    创建时刻
--
-- 索引：
--   uniq(key_prefix) — 校验时 O(1) 直查
--   user_id — ListByUser
--   tenant_id partial — 管理员按租户过滤
--
-- RLS：本 PR 未启；待 tenancy 模块统一加 policy。

-- +goose Up

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    key_prefix CHAR(8) NOT NULL,
    secret_hash CHAR(64) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT api_keys_prefix_uniq UNIQUE (key_prefix),
    CONSTRAINT api_keys_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT api_keys_secret_hex CHECK (secret_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT api_keys_scopes_is_array CHECK (jsonb_typeof(scopes) = 'array')
);

CREATE INDEX idx_api_keys_user ON api_keys (user_id);
CREATE INDEX idx_api_keys_tenant ON api_keys (tenant_id) WHERE tenant_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS api_keys;
