-- 创建 nodes 表（LLD 11 §3.5）。
--
-- Node 是租户下的扫描节点（Agent）。MVP 阶段允许 SA 手动注册（先填 name +
-- version），跳过完整的 RegistrationToken / mTLS PKI 流程（待 PR-T4-B/T4-D 接）。
--
-- 字段：
--   id              UUID PK
--   tenant_id       UUID FK accounts CASCADE
--   name            租户内唯一；用户可见；不可变
--   version         Agent 版本字串（手动注册时由 SA 填，后续真节点上报覆盖）
--   capabilities    JSONB 数组（如 ["scan:web", "scan:port"]）；MVP 仅持久
--   status          pending(token 已发未连) / online / offline / disabled
--   last_seen_at    最后心跳 / 状态更新时刻；MVP 手动更新
--   created_by      创建者 user_id（无 FK）
--   created_at / updated_at / deleted_at
--
-- 索引：
--   uniq(tenant_id, lower(name)) WHERE deleted_at IS NULL
--   idx(tenant_id) WHERE deleted_at IS NULL
--   idx(status) WHERE deleted_at IS NULL

-- +goose Up

CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    version VARCHAR(32) NOT NULL DEFAULT '',
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    last_seen_at TIMESTAMPTZ,

    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT nodes_status_valid CHECK (status IN ('pending', 'online', 'offline', 'disabled')),
    CONSTRAINT nodes_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT nodes_capabilities_is_array CHECK (jsonb_typeof(capabilities) = 'array')
);

CREATE UNIQUE INDEX nodes_tenant_name_uniq
    ON nodes (tenant_id, lower(name))
    WHERE deleted_at IS NULL;

CREATE INDEX idx_nodes_tenant ON nodes (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_nodes_status ON nodes (status) WHERE deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON nodes TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON nodes TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS nodes;
