-- 创建 scan_tasks 表（PR-S1 扫描调度入口）。
--
-- MVP 范围：仅 task 元数据 + 状态机；不含 task_assignments / 执行记录 / 结果。
-- 后续 PR：
--   PR-S2 task_assignments（项目白名单 → 选 online 节点 → 写分发表）
--   PR-S3 NodeAgent.PullTasks / ReportTaskProgress
--   PR-S4 task_results / 与 ES 对接
--
-- 字段：
--   id              UUID PK
--   tenant_id       UUID FK accounts CASCADE（同租户隔离）
--   project_id      UUID FK projects CASCADE（必属一个项目；删项目 → 任务级联软删）
--   name            VARCHAR(128) 任务名（项目内可重；不强制唯一）
--   kind            VARCHAR(32) 扫描类型（port_scan / web_crawl / ...）
--   target          TEXT 目标字串（host / IP / CIDR / URL）
--   target_kind     VARCHAR(16) host / ip / cidr / url
--   status          pending / running / completed / failed / canceled
--   schedule_kind   immediate / cron（MVP 仅 immediate）
--   cron_expr       VARCHAR(64)（schedule_kind=cron 时；MVP NULL）
--   settings        JSONB 任务级配置（端口范围 / 并发 / 等）
--   created_by      UUID FK users
--   created_at / updated_at / started_at / finished_at / deleted_at
--
-- 索引：
--   idx(project_id, status) WHERE deleted_at IS NULL — 详情页 / 过滤主路径
--   idx(tenant_id) WHERE deleted_at IS NULL — 跨项目聚合统计
--   idx(status) WHERE deleted_at IS NULL AND status IN (pending, running) — 调度器扫待发任务

-- +goose Up

CREATE TABLE scan_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    target TEXT NOT NULL,
    target_kind VARCHAR(16) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',

    schedule_kind VARCHAR(16) NOT NULL DEFAULT 'immediate',
    cron_expr VARCHAR(64),

    settings JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_by UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,

    CONSTRAINT scan_tasks_status_valid CHECK (status IN
        ('pending', 'running', 'completed', 'failed', 'canceled')),
    CONSTRAINT scan_tasks_kind_valid CHECK (kind IN
        ('port_scan', 'web_crawl', 'subdomain', 'fingerprint')),
    CONSTRAINT scan_tasks_target_kind_valid CHECK (target_kind IN
        ('host', 'ip', 'cidr', 'url')),
    CONSTRAINT scan_tasks_schedule_kind_valid CHECK (schedule_kind IN
        ('immediate', 'cron')),
    CONSTRAINT scan_tasks_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT scan_tasks_target_nonempty CHECK (length(target) > 0),
    CONSTRAINT scan_tasks_settings_is_object CHECK (jsonb_typeof(settings) = 'object')
);

CREATE INDEX idx_scan_tasks_project_status
    ON scan_tasks (project_id, status)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_scan_tasks_tenant
    ON scan_tasks (tenant_id)
    WHERE deleted_at IS NULL;

CREATE INDEX idx_scan_tasks_dispatchable
    ON scan_tasks (created_at)
    WHERE deleted_at IS NULL AND status IN ('pending', 'running');

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_tasks TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_tasks TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS scan_tasks;
