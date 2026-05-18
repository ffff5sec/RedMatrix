-- PR-S33：审计日志（hash 链）。
--
-- 设计：
--   - 每条 audit 行算 hash = sha256(canonical(action, resource_kind, ..., prev_hash))
--   - prev_hash 来自该 tenant 上一条 audit；首条 prev_hash 用 64 个 '0'
--   - 校验：扫一段连续行重算 hash 与列对比；任意一行被改 → 后续全部断链
--   - 写入路径：service.Log(ctx, event) — 全部走单 PG TX 拿 prev_hash 防并发竞态
--
-- 不可变性 MVP：单纯应用层约束 + 无 UPDATE/DELETE SQL；后续若需更强可加 trigger / WORM。

-- +goose Up

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- 谁
    actor_user_id UUID,                     -- 已登录用户；webhook / cron 可为 NULL
    actor_username VARCHAR(64) NOT NULL DEFAULT '',
    actor_ip VARCHAR(45),                   -- IPv6 max
    user_agent VARCHAR(256),

    -- 做了什么
    action VARCHAR(64) NOT NULL,            -- login / task_create / suite_run / finding_transition / ...
    resource_kind VARCHAR(32) NOT NULL,     -- task / suite / finding / user / session / ...
    resource_id VARCHAR(64),                -- 资源 ID（UUID / slug）

    -- 范围（用于过滤 + RBAC 收紧）
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE SET NULL,

    -- 业务 payload（自由 JSON）
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- hash 链
    prev_hash VARCHAR(64) NOT NULL,         -- 上一条 audit.hash；首条全 '0'
    hash VARCHAR(64) NOT NULL UNIQUE,       -- sha256 hex；UNIQUE 防 race 同 prev_hash

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT audit_action_nonempty CHECK (length(trim(action)) > 0),
    CONSTRAINT audit_resource_kind_nonempty CHECK (length(trim(resource_kind)) > 0),
    CONSTRAINT audit_hash_hex CHECK (hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_prev_hash_hex CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_payload_obj CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX idx_audit_tenant_recent ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_actor ON audit_logs (actor_user_id, created_at DESC) WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_action ON audit_logs (action, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs (resource_kind, resource_id) WHERE resource_id IS NOT NULL;
CREATE INDEX idx_audit_project ON audit_logs (project_id, created_at DESC) WHERE project_id IS NOT NULL;

-- 拒绝任何 UPDATE / DELETE：trigger 拒绝改动（hash 链完整性的最低保障）。
-- 注：DROP / TRUNCATE 仍可（DBA 责任域）；应用层不暴露任何修改接口。
-- 用 goose StatementBegin/End 标记 plpgsql 块（含 $$ 引号 + 多行）
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_logs_no_change() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_logs_block_update BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_no_change();
CREATE TRIGGER audit_logs_block_delete BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_no_change();

-- +goose Down

DROP TRIGGER IF EXISTS audit_logs_block_delete ON audit_logs;
DROP TRIGGER IF EXISTS audit_logs_block_update ON audit_logs;
DROP FUNCTION IF EXISTS audit_logs_no_change();
DROP TABLE IF EXISTS audit_logs;
