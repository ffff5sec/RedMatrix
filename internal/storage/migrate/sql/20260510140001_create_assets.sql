-- 创建 assets 表（PR-S8 资产视图）。
--
-- 设计：
--   assets 是 scan_results 的"上一层"派生视图——同一 host / url / 子域只
--   存一行；每次 ReportResults 触发 UPSERT 累计 result_count + 推 last_seen。
--
-- 资产类型（kind）：
--   - host:      port_scan / fingerprint 的 host 字段（小写）
--   - subdomain: subdomain 任务的 name 字段（小写）—— 与 host 同 namespace？
--                MVP 分两类便于前端 tab 区分；同 value 不同 kind 不去重
--   - url:       web_crawl 的 url 字段（去 query / fragment 后规范化）
--
-- 唯一性：(tenant_id, project_id, kind, value) —— 跨 task 同资产去重
--
-- 索引：
--   - UNIQUE(tenant, project, kind, value)：UPSERT 必需 + 详情查
--   - (tenant, project, last_seen DESC)：列表页默认按"最近活跃"排序
--   - (kind, last_seen DESC)：跨 tenant SOC 视角（SA / 审计员）

-- +goose Up

CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind VARCHAR(32) NOT NULL,
    value VARCHAR(2048) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_count INTEGER NOT NULL DEFAULT 0,

    CONSTRAINT assets_kind_valid CHECK (kind IN ('host', 'subdomain', 'url')),
    CONSTRAINT assets_value_nonempty CHECK (length(value) > 0)
);

CREATE UNIQUE INDEX idx_assets_unique
    ON assets (tenant_id, project_id, kind, value);
CREATE INDEX idx_assets_last_seen
    ON assets (tenant_id, project_id, last_seen DESC);
CREATE INDEX idx_assets_kind_last_seen
    ON assets (kind, last_seen DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS assets;
