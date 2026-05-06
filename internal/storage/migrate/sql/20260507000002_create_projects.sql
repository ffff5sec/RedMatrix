-- 创建 projects 表（LLD 11 §3.2 / §4）。
--
-- Project 是租户内的资产边界。MVP 默认 1 个 active account，所有 project 挂它下面。
--
-- 字段：
--   id            UUID PK
--   tenant_id     UUID FK → accounts(id) ON DELETE CASCADE（账户硬删 → 项目跟着删）
--   name          租户内唯一（活项目）；用户可见
--   description   ≤ 2000 字符可空
--   status        active / archived；状态机见 LLD 11 §4.1
--   settings      项目级配置（如默认阈值）；MVP 空对象
--   stats_cache   异步刷新的缓存（资产数 / 任务数 / running 任务）；MVP 留空对象
--   created_by    创建者 user_id（无 FK，避免与 users 软删冲突；审计字段语义）
--   timestamps    created_at / updated_at
--   archived_at   归档时刻；status=active 时必空
--   deleted_at    软删；查询默认排除（删项目 = SoftDelete + cascade clean，
--                 LLD 11 §4.4，MVP 仅本表 soft delete，外键级联属后续 PR）
--
-- 索引 / 约束：
--   uniq(tenant_id, lower(name)) WHERE deleted_at IS NULL —— 名称在租户内唯一（活项目）
--   idx(tenant_id) WHERE deleted_at IS NULL —— 列表查询主路径
--   idx(status) WHERE deleted_at IS NULL —— 过滤 archived

-- +goose Up

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    stats_cache JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,

    CONSTRAINT projects_status_valid CHECK (status IN ('active', 'archived')),
    CONSTRAINT projects_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT projects_desc_max CHECK (length(description) <= 2000),
    CONSTRAINT projects_settings_is_object CHECK (jsonb_typeof(settings) = 'object'),
    CONSTRAINT projects_stats_is_object CHECK (jsonb_typeof(stats_cache) = 'object'),
    -- archived_at 必须与 status=archived 同步（双向）
    CONSTRAINT projects_archived_consistency CHECK (
        (status = 'archived' AND archived_at IS NOT NULL)
        OR (status = 'active' AND archived_at IS NULL)
    )
);

-- 名称在租户内唯一（活项目）；soft-deleted 不参与 → 同名可复用
CREATE UNIQUE INDEX projects_tenant_name_uniq
    ON projects (tenant_id, lower(name))
    WHERE deleted_at IS NULL;

CREATE INDEX idx_projects_tenant ON projects (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_projects_status ON projects (status) WHERE deleted_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON projects TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON projects TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS projects;
