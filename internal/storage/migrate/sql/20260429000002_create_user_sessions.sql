-- 创建 user_sessions 表（LLD 10 §3.4 / 7.1）。
--
-- Session 是登录元数据 + 审计辅助，不参与 JWT 吊销判定（吊销靠 user.token_version）。
-- 字段：
--   id            UUID PK，写入 JWT.sid claim 用于审计回溯
--   tenant_id     UUID nullable（SuperAdmin 跨租户）
--   user_id       UUID FK → users(id) ON DELETE CASCADE
--   user_agent    UA 字串（仅显示）
--   ip            INET（IPv4 / IPv6 都装得下）
--   issued_at     登录时刻
--   last_seen_at  最后活动；用于 "活跃 session" 列表
--   token_version 签发时的 user.token_version 快照
--   expires_at    JWT 过期时刻；列表查询 / 清理任务用
--
-- 索引：
--   user_id+expires_at desc：列表 / 单用户活跃 session
--   tenant_id partial：管理员按租户过滤
--   expires_at：定期清理过期 session 任务

-- +goose Up

CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_agent TEXT NOT NULL DEFAULT '',
    ip INET,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    token_version BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,

    CONSTRAINT user_sessions_token_version_nonneg CHECK (token_version >= 0),
    CONSTRAINT user_sessions_expires_after_issued CHECK (expires_at > issued_at)
);

CREATE INDEX idx_sessions_user_active ON user_sessions (user_id, expires_at DESC);
CREATE INDEX idx_sessions_tenant ON user_sessions (tenant_id) WHERE tenant_id IS NOT NULL;
CREATE INDEX idx_sessions_expires ON user_sessions (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_sessions TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_sessions TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS user_sessions;
