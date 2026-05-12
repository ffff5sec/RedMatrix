-- PR-S26：漏洞工作流（finding 状态机）。
--
-- 设计：
--   - findings 表：每个独特 (template_id, host, project_id) 1 行；同一漏洞重复扫描去重，
--     仅刷新 last_seen_at + occurrence_count
--   - finding_events 表：状态变更 / 评论 / 指派事件流；按时间排序作 timeline
--
-- 状态机：
--   open ─► triaged ─► confirmed ─► fixed ─► open (reopen)
--                  ╲       ╲             ╱
--                   ╲       ╲           ╱
--                    ────► false_positive (终态，但可 reopen → open)
--
-- 自动创建：scan ReportResults 高危 result（nuclei severity high/critical）→
-- service.UpsertFromResult(template_id, host, project_id) → 新建或更新 last_seen。

-- +goose Up

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,

    -- 去重 key：同 template 同 host 同 project 视为同一 finding
    -- 不用 UUID 类型而用 VARCHAR，因 template_id 是 nuclei slug（非 UUID）
    dedup_key VARCHAR(256) NOT NULL,

    -- 来源信息
    template_id VARCHAR(128) NOT NULL,    -- nuclei template slug，例如 'CVE-2021-44228'
    source_result_id UUID,                -- 首次创建时的 scan_result.id（FK SET NULL）
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- 元数据
    severity VARCHAR(16) NOT NULL,        -- low / medium / high / critical
    title VARCHAR(256) NOT NULL,
    host VARCHAR(256) NOT NULL,
    description TEXT,
    reference TEXT,                       -- nuclei info.reference 拼接

    -- 状态机
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    assignee_id UUID,                     -- 用户 id（不挂 FK，保留软引用避免 user 删后级联）

    -- 时间
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    occurrence_count INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT finding_status_valid CHECK (status IN ('open','triaged','confirmed','false_positive','fixed')),
    CONSTRAINT finding_severity_valid CHECK (severity IN ('info','low','medium','high','critical'))
);

-- dedup_key 在同租户内唯一（不分项目；同 host 同 template 跨项目算不同 finding）
CREATE UNIQUE INDEX idx_findings_dedup ON findings (tenant_id, project_id, dedup_key) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_tenant_status ON findings (tenant_id, status, last_seen_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_project ON findings (project_id, last_seen_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_severity ON findings (severity, status) WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_assignee ON findings (assignee_id) WHERE assignee_id IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE finding_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    actor_id UUID,                        -- 谁触发；自动创建时 NULL（系统）

    -- 事件 kind: status_change / comment / assignee_change / created / occurrence
    kind VARCHAR(20) NOT NULL,

    -- 状态变更专用
    from_status VARCHAR(20),
    to_status VARCHAR(20),

    -- 指派变更专用
    from_assignee UUID,
    to_assignee UUID,

    -- 评论 body / 任意 kind 的人类可读补充
    body TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT finding_event_kind_valid CHECK (kind IN ('created','status_change','comment','assignee_change','occurrence'))
);

CREATE INDEX idx_finding_events_finding ON finding_events (finding_id, created_at DESC);

-- +goose Down

DROP TABLE IF EXISTS finding_events;
DROP TABLE IF EXISTS findings;
