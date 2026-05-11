-- PR-S23：扫描套件（pipeline）—— 一键串起 N kind 的扫描。
--
-- 设计：
--   - scan_suites  套件模板（kinds + 默认 settings）；project_id 可空 = 跨项目
--   - scan_suite_runs 一次 RunSuite 创建 1 行，记 targets + 聚合 status
--   - scan_tasks.suite_run_id 子 task 反查 run（nullable，独立 task 不挂套件）
--
-- aggregator：子 task 终态时反推 run.status（running → completed / partial_failed）
-- aggregator 逻辑放在 service 层；schema 仅存 status 字段

-- +goose Up

CREATE TABLE scan_suites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- project_id NULL = 跨项目共享（同租户内所有 PA 可见 + 可用）
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    -- kinds 套件包含的 task kind 序列；MVP 全并行触发，顺序仅展示用
    kinds TEXT[] NOT NULL,
    -- 默认 target_kind；RunSuite 时若 targets 形态混杂可被 caller 覆盖
    target_kind VARCHAR(16) NOT NULL,
    -- per-kind 默认 settings：{"port_scan": {...}, "nuclei": {...}}
    -- RunSuite 时合并到每个子 task 的 settings 字段
    default_settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT scan_suites_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT scan_suites_kinds_nonempty CHECK (cardinality(kinds) > 0),
    CONSTRAINT scan_suites_target_kind_valid CHECK (target_kind IN
        ('host', 'ip', 'cidr', 'url')),
    CONSTRAINT scan_suites_default_settings_is_object CHECK
        (jsonb_typeof(default_settings) = 'object')
);

CREATE INDEX idx_scan_suites_tenant
    ON scan_suites (tenant_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_scan_suites_project
    ON scan_suites (project_id)
    WHERE deleted_at IS NULL AND project_id IS NOT NULL;


CREATE TABLE scan_suite_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suite_id UUID NOT NULL REFERENCES scan_suites(id) ON DELETE RESTRICT,
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    targets TEXT[] NOT NULL,
    -- status 状态机：
    --   pending        — 子 task 全 pending
    --   running        — 任意子 task pulled/running
    --   completed      — 所有子 task completed
    --   partial_failed — 至少 1 个 failed 且至少 1 个 completed
    --   failed         — 所有子 task failed
    --   canceled       — 所有子 task canceled
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,

    CONSTRAINT scan_suite_runs_status_valid CHECK (status IN
        ('pending', 'running', 'completed', 'partial_failed', 'failed', 'canceled')),
    CONSTRAINT scan_suite_runs_targets_nonempty CHECK (cardinality(targets) > 0)
);

CREATE INDEX idx_scan_suite_runs_suite
    ON scan_suite_runs (suite_id, created_at DESC);
CREATE INDEX idx_scan_suite_runs_tenant
    ON scan_suite_runs (tenant_id, created_at DESC);
CREATE INDEX idx_scan_suite_runs_project
    ON scan_suite_runs (project_id, created_at DESC);


-- 子 task 反查 suite_run。nullable：独立 task 仍走老路径。
-- ON DELETE SET NULL：suite_run 删了 task 仍在（保留扫描结果）
ALTER TABLE scan_tasks
    ADD COLUMN suite_run_id UUID REFERENCES scan_suite_runs(id) ON DELETE SET NULL;

CREATE INDEX idx_scan_tasks_suite_run
    ON scan_tasks (suite_run_id)
    WHERE suite_run_id IS NOT NULL AND deleted_at IS NULL;


GRANT SELECT, INSERT, UPDATE, DELETE ON scan_suites TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_suites TO redmatrix_maintenance;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_suite_runs TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_suite_runs TO redmatrix_maintenance;

-- +goose Down

DROP INDEX IF EXISTS idx_scan_tasks_suite_run;
ALTER TABLE scan_tasks DROP COLUMN IF EXISTS suite_run_id;
DROP TABLE IF EXISTS scan_suite_runs;
DROP TABLE IF EXISTS scan_suites;
