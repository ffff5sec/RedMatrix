-- 创建 outbox_events 表，承接 LLD 20-eventbus-impl §6 Outbox 模式。
--
-- 流转：
--   1. 业务在 PG TX 中调 PublishTx(tx, ev) → 写一行（同 TX 原子性保证）
--   2. TX commit 后 Relay 轮询 next_attempt_at <= now() 且未 published / failed 的行
--   3. Relay 通过 Registry 反序列化 payload + 用 *Bus 同步分发
--   4. 成功 → published_at = now()
--   5. 失败 → attempts++, last_error, next_attempt_at += backoff
--      attempts ≥ MaxAttempts 时 failed_permanently_at = now()（DLQ 替代品）
--
-- 不变量：
--   - 只追加 + 标记。已 published 的行保留作审计 / 重投取证（保留期由 cleanup cron 控制）
--   - tenant_id 可空（平台级事件如系统启动 / 密钥轮换无租户）
--   - trace_id 关联 X-Request-ID / log.RequestID 便于跨服务链路追踪

-- +goose Up

CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    topic TEXT NOT NULL,
    payload JSONB NOT NULL,
    tenant_id UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    failed_permanently_at TIMESTAMPTZ,

    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,

    trace_id TEXT
);

-- 仅未完成事件参与 Relay 扫描；published / failed_permanently 行由 cleanup 任务批量删。
CREATE INDEX idx_outbox_pending
    ON outbox_events (next_attempt_at)
    WHERE published_at IS NULL AND failed_permanently_at IS NULL;

CREATE INDEX idx_outbox_topic ON outbox_events (topic);
CREATE INDEX idx_outbox_tenant
    ON outbox_events (tenant_id)
    WHERE tenant_id IS NOT NULL;

-- 注：本表不启 RLS。outbox 是平台级队列；business code 通过 PublishTx 写入，
-- Relay 由 maintenance role 跨租户读。详见 22-rls-implementation.md §3.2 类别 A。
GRANT SELECT, INSERT, UPDATE, DELETE ON outbox_events TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON outbox_events TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS outbox_events;
