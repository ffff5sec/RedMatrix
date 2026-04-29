-- 创建 users 表，承接 LLD 10-identity-module §4.3 + 01 §1.2.1。
--
-- 字段：
--   id                   UUID PK
--   tenant_id            UUID nullable（SuperAdmin 跨租户，无 tenant_id）
--   username             3-32 字符全局唯一（LLD 10 §4.3）
--   password_hash        argon2id PHC string
--   email                可选；纯 NULL 或合法邮箱
--   role                 SUPER_ADMIN / PROJECT_ADMIN / TENANT_AUDITOR / PLATFORM_AUDITOR
--   status               active / disabled / pending_deletion
--   token_version        JWT 失效计数（LLD 10 §5.4 — 改密 / 强制下线 时 ++）
--   must_change_password bootstrap admin 首登强制改密
--   last_login_at        最近一次成功登录（昵称访问 / 审计用）
--   created_at / updated_at
--
-- 索引：
--   uniq(username) 全局唯一
--   role / tenant_id / email 用于过滤查询
--
-- 注：本表不在本 PR 启 RLS。tenancy 模块（LLD 11，下个 module）落地时统一加
-- RLS policy + redmatrix_app session var 注入。详见 22-rls-implementation.md §3.2。

-- +goose Up

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID,
    username VARCHAR(32) NOT NULL,
    password_hash TEXT NOT NULL,
    email VARCHAR(254),
    role VARCHAR(32) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    token_version INTEGER NOT NULL DEFAULT 0,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,

    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT users_username_uniq UNIQUE (username),
    CONSTRAINT users_role_valid CHECK (role IN
        ('SUPER_ADMIN', 'PROJECT_ADMIN', 'TENANT_AUDITOR', 'PLATFORM_AUDITOR')),
    CONSTRAINT users_status_valid CHECK (status IN
        ('active', 'disabled', 'pending_deletion')),
    -- SuperAdmin 必须 tenant_id IS NULL；其他角色必须非空
    CONSTRAINT users_tenant_role_consistency CHECK (
        (role = 'SUPER_ADMIN' AND tenant_id IS NULL)
        OR (role <> 'SUPER_ADMIN' AND tenant_id IS NOT NULL)
    )
);

CREATE INDEX idx_users_role ON users (role);
CREATE INDEX idx_users_tenant ON users (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_users_email ON users (email) WHERE email IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS users;
