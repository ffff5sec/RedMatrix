-- 创建 registration_tokens 表（LLD 11 §3.7 / §7）。
--
-- 一次性令牌，让真节点（Agent）首次连接 Server 时换取节点身份（PR-T4-B 创建
-- Node 行；PR-T4-D 加 mTLS 证书签发）。
--
-- 字段：
--   id          UUID PK
--   tenant_id   UUID FK accounts CASCADE
--   name        SA 给的描述名（如 "Q1 batch"）
--   token_hash  SHA-256(plaintext) hex；UNIQUE 防撞
--   expires_at  TTL 到期；超过即不可兑换（默认 1h，最大 24h）
--   used_at     兑换成功时刻；非空 = 已用，单次性
--   revoked_at  人为撤销；非空 = 撤销
--   created_by  创建者 user_id（无 FK；用户硬删后保留以便审计）
--   created_at
--
-- 校验逻辑（service 层）：valid = used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
--
-- 不存 plaintext。仅一次性返给 SA（创建时返）。

-- +goose Up

CREATE TABLE registration_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    token_hash CHAR(64) NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT registration_tokens_hash_uniq UNIQUE (token_hash),
    CONSTRAINT registration_tokens_name_nonempty CHECK (length(name) > 0),
    CONSTRAINT registration_tokens_hash_hex CHECK (token_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX idx_registration_tokens_tenant
    ON registration_tokens (tenant_id);

CREATE INDEX idx_registration_tokens_expires
    ON registration_tokens (expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON registration_tokens TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON registration_tokens TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS registration_tokens;
