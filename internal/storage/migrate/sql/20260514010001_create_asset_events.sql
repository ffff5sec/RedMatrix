-- PR-S57 asset_events 表（SPEC §2.7 资产变更事件流，MVP 一期）。
--
-- 设计：
--   每次 asset.UpsertFromResults 后，service 比对 PG 返回的 is_new 标记，
--   对新插入资产派生事件入此表。订阅模块（notify）按 event_kind 过滤推送
--   告警；前端时间线按 created_at DESC 列。
--
-- 一期 5 类（PR-S57 实现 3 个新增类；PR-S58+ 实现消失类 / 证书到期）：
--   - asset_new_subdomain : 首次发现子域名
--   - asset_new_port      : 主机首次开放端口（不区分服务）
--   - asset_new_service   : 主机首次出现某协议服务（http/ssh/mysql/...）
--   - asset_disappeared   : 资产 last_seen 超阈值（PR-S58 sweeper 写）
--   - cert_expiring_soon  : tls_scan 探到 not_after < now+30d（PR-S58 写）
--
-- 索引：
--   - (tenant, project, created_at DESC): 时间线列表默认排序
--   - (asset_id):                          某资产历史事件
--   - (event_kind, created_at DESC):       按事件类型过滤 + 告警引擎扫
--
-- 注：不做 append-only PG trigger（与 audit_logs 不同）—— asset 事件不是合规
-- 强一致敏感数据，admin 误删可接受。

-- +goose Up

CREATE TABLE asset_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    -- asset_id 可空：消失类事件触发时 asset 还在；将来真删时设 NULL
    -- 不级联（资产删了事件仍保留作历史）
    asset_id UUID NULL REFERENCES assets(id) ON DELETE SET NULL,
    event_kind VARCHAR(32) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT asset_events_kind_valid CHECK (event_kind IN (
        'asset_new_subdomain',
        'asset_new_port',
        'asset_new_service',
        'asset_disappeared',
        'cert_expiring_soon'
    ))
);

CREATE INDEX idx_asset_events_timeline
    ON asset_events (tenant_id, project_id, created_at DESC);
CREATE INDEX idx_asset_events_by_asset
    ON asset_events (asset_id);
CREATE INDEX idx_asset_events_kind
    ON asset_events (event_kind, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON asset_events TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_events TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS asset_events;
