-- 创建 accounts 表（LLD 11 §3.1）。
--
-- accounts 是租户聚合根。MVP 单租户：bootstrap 期间 ensure 一个 "default"
-- account（slug='default'），所有非 SuperAdmin 用户挂在它下面。Phase 2 多租户
-- 时 platform admin 可创建更多。
--
-- 字段：
--   id            UUID PK；bootstrap 期写入固定 UUID 让前端可硬编码 tenant_id
--   slug          短字串唯一标识（[a-z0-9-]，3-32 字符）；URL 友好
--   display_name  人类可读名（如 "RedMatrix"）
--   plan          配额档位预留：standard / enterprise
--   status        active / suspended / disabled（部署级管控）
--   quota_*       MVP 不强制；预留供后续 Quota Service 用
--   settings      tenant 级配置（如默认 captcha 策略覆盖）；MVP 空对象
--   created_at / updated_at / deleted_at
--
-- 关系：users.tenant_id 指向 accounts.id（无 FK；schema 演进时再加）。
-- RLS：本 PR 未启；待 tenancy interceptor + tenant session var 落地后统一加。

-- +goose Up

CREATE TABLE accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(32) NOT NULL,
    display_name VARCHAR(128) NOT NULL,
    plan VARCHAR(32) NOT NULL DEFAULT 'standard',
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    quota_users INTEGER NOT NULL DEFAULT 0,
    quota_projects INTEGER NOT NULL DEFAULT 0,
    quota_assets BIGINT NOT NULL DEFAULT 0,

    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT accounts_slug_uniq UNIQUE (slug),
    CONSTRAINT accounts_slug_format CHECK (slug ~ '^[a-z0-9-]{3,32}$'),
    CONSTRAINT accounts_status_valid CHECK (status IN ('active', 'suspended', 'disabled')),
    CONSTRAINT accounts_settings_is_object CHECK (jsonb_typeof(settings) = 'object')
);

CREATE INDEX idx_accounts_status ON accounts (status) WHERE deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON accounts TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON accounts TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS accounts;
