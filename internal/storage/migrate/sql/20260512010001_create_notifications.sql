-- PR-S25：通知告警（Webhook + 邮件）。
--
-- 设计：
--   - notification_subscriptions 订阅规则模板：tenant + 可选 project + event_kinds + channel + config(jsonb)
--   - notification_deliveries 一次投递：status pending → sent / failed → 重试 / dead
--
-- 发送路径：
--   1. 事件总线触发 → Notifier.Notify(ev) → match subscriptions → INSERT deliveries(pending, scheduled_at=now)
--   2. retry sweeper 30s 轮询：scheduled_at ≤ now 的 pending/failed → adapter dispatch
--      - 成功 → status=sent
--      - 失败 → attempts++；attempts<5 → 退避 1m/5m/30m/2h/12h；attempts≥5 → status=dead
--
-- 通道：
--   - webhook：config = { "url": "https://...", "secret": "..." (可选 HMAC) }
--   - email：config = { "to": ["a@x", "b@y"] }；SMTP 配置走 env（NOTIFY_SMTP_*）

-- +goose Up

CREATE TABLE notification_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- NULL = 全租户；非空 = 限项目
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    -- 监听的事件 kind（task_completed / task_failed / finding_high）
    event_kinds TEXT[] NOT NULL,
    -- 通道类型（webhook / email）
    channel VARCHAR(16) NOT NULL,
    -- 通道配置（按 channel 不同 schema 不同）
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- 过滤器（如 { "min_severity": "high" }）
    filter JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT notif_sub_channel_valid CHECK (channel IN ('webhook', 'email')),
    CONSTRAINT notif_sub_event_kinds_nonempty CHECK (array_length(event_kinds, 1) >= 1),
    CONSTRAINT notif_sub_config_is_object CHECK (jsonb_typeof(config) = 'object'),
    CONSTRAINT notif_sub_filter_is_object CHECK (jsonb_typeof(filter) = 'object')
);

CREATE INDEX idx_notif_sub_tenant ON notification_subscriptions (tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_notif_sub_tenant_project ON notification_subscriptions (tenant_id, project_id) WHERE deleted_at IS NULL;

CREATE TABLE notification_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID NOT NULL REFERENCES notification_subscriptions(id) ON DELETE CASCADE,
    -- 冗余 tenant/project 方便查询 + RBAC
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    event_kind VARCHAR(32) NOT NULL,
    event_topic VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ,

    CONSTRAINT notif_del_status_valid CHECK (status IN ('pending', 'sent', 'failed', 'dead')),
    CONSTRAINT notif_del_payload_is_object CHECK (jsonb_typeof(payload) = 'object')
);

CREATE INDEX idx_notif_del_due ON notification_deliveries (scheduled_at)
    WHERE status IN ('pending', 'failed');
CREATE INDEX idx_notif_del_tenant_recent ON notification_deliveries (tenant_id, created_at DESC);
CREATE INDEX idx_notif_del_subscription ON notification_deliveries (subscription_id, created_at DESC);

-- +goose Down

DROP TABLE IF EXISTS notification_deliveries;
DROP TABLE IF EXISTS notification_subscriptions;
