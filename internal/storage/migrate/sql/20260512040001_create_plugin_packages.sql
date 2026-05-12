-- PR-S28：Agent 插件包分发 + 升级。
--
-- 设计：
--   - plugin_signing_keys ed25519 公钥分发；server 私钥走 env (PLUGIN_SIGNING_KEY_BASE64)
--   - plugin_packages 每个 (slug, version, platform) 一行；MinIO 存 binary
--
-- 流程：
--   - 上传：admin → server 接收 binary → sha256 → ed25519 私钥签 → MinIO put + INSERT plugin_packages
--   - 拉取：agent → ListLatest(slug, platform) → GetDownloadURL → 校 sha256 + ed25519 签 → 安装
--   - 公钥分发：agent 启动时一次性 GetPublicKey 缓存（mTLS 通道保证不被中间人）

-- +goose Up

CREATE TABLE plugin_signing_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id VARCHAR(64) NOT NULL UNIQUE,        -- 短标识，如 'redmatrix-2026'
    public_key TEXT NOT NULL,                  -- base64 ed25519 公钥（32 字节原始）
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_plugin_signing_keys_active
    ON plugin_signing_keys (key_id) WHERE revoked_at IS NULL;

CREATE TABLE plugin_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- 插件标识
    slug VARCHAR(64) NOT NULL,          -- 'subfinder' / 'httpx' / 'nuclei' / 'nmap'
    version VARCHAR(32) NOT NULL,       -- '2.6.3' / 'v2.6.3'（SemVer-friendly）
    platform VARCHAR(32) NOT NULL,      -- 'linux_amd64' / 'linux_arm64' / 'darwin_amd64'

    -- MinIO 存储
    artifact_key VARCHAR(256) NOT NULL, -- 'plugins/<slug>/<version>/<platform>/<filename>'
    sha256 VARCHAR(64) NOT NULL,        -- 32 字节 hex
    signature TEXT NOT NULL,            -- base64 ed25519 签名（针对 sha256 hex 字符串签）
    signing_key_id VARCHAR(64) NOT NULL REFERENCES plugin_signing_keys(key_id),
    size_bytes BIGINT NOT NULL,

    -- 元数据
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,  -- false = 不分发给 agent

    -- 审计
    uploaded_by UUID,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deprecated_at TIMESTAMPTZ,

    CONSTRAINT plugin_pkg_unique UNIQUE (slug, version, platform),
    CONSTRAINT plugin_pkg_sha256_hex CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT plugin_pkg_size_pos CHECK (size_bytes > 0)
);

CREATE INDEX idx_plugin_pkg_slug_active ON plugin_packages (slug, platform, is_active)
    WHERE deprecated_at IS NULL;
CREATE INDEX idx_plugin_pkg_recent ON plugin_packages (uploaded_at DESC);

-- +goose Down

DROP TABLE IF EXISTS plugin_packages;
DROP TABLE IF EXISTS plugin_signing_keys;
