-- 创建 node_certificates 表（LLD 11 §3.6 / §11）。
--
-- 节点 mTLS 证书入库（仅 cert + serial + fingerprint；私钥永不入库——
-- Agent 端持有，Server 端仅校验 cert 链 + 查 revoked_at）。
--
-- 字段：
--   id              UUID PK
--   node_id         UUID FK → nodes(id) ON DELETE CASCADE
--   serial_number   X.509 SerialNumber 的十进制 / hex 字符串；UNIQUE
--   fingerprint     SHA-256(DER) hex；64 字符 UNIQUE；mTLS 校验快查
--   common_name     CN（通常 == node_id；冗余存便于审计）
--   cert_pem        PEM 全文（含 BEGIN/END）
--   issued_at       签发时刻
--   expires_at      过期时刻；后续 cron 续期
--   revoked_at      撤销时刻；非空 → 被吊销
--   issued_by_token UUID nullable；FK → registration_tokens(id) ON DELETE SET NULL
--                   审计：本 cert 是哪张令牌兑换出来的；token 删时保留 cert 记录
--   created_at
--
-- 索引：
--   uniq(serial_number) — Server 反查
--   uniq(fingerprint) — mTLS hot path（Heartbeat 校验）
--   idx(node_id) — ListByNode
--   idx(expires_at) WHERE revoked_at IS NULL — 续期 cron 扫即将过期

-- +goose Up

CREATE TABLE node_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    serial_number TEXT NOT NULL,
    fingerprint CHAR(64) NOT NULL,
    common_name TEXT NOT NULL,
    cert_pem TEXT NOT NULL,

    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,

    issued_by_token UUID REFERENCES registration_tokens(id) ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT node_certs_serial_uniq UNIQUE (serial_number),
    CONSTRAINT node_certs_fingerprint_uniq UNIQUE (fingerprint),
    CONSTRAINT node_certs_fingerprint_hex CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    CONSTRAINT node_certs_cn_nonempty CHECK (length(common_name) > 0)
);

CREATE INDEX idx_node_certs_node ON node_certificates (node_id);
CREATE INDEX idx_node_certs_expires
    ON node_certificates (expires_at)
    WHERE revoked_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON node_certificates TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_certificates TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS node_certificates;
