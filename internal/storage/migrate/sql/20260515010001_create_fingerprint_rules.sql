-- 创建 fingerprint_rules 表（PR-S74 用户自定义指纹规则）。
--
-- 设计：
--   - 内嵌规则在 internal/fingerprint/rules.yaml（go:embed，不入表）
--   - 自定义规则按 tenant 隔离，与内嵌规则在 match 时合并
--   - 同 tenant 下 name 唯一（含软删保留）
--
-- 字段：
--   name           显示名 + 命中后 tech 标签值
--   fields         限制查的字段（body / title / webserver / headers / ...）；
--                  空 = 任意字符串字段
--   keyword        子串匹配
--   case_sensitive false 默认不区分大小写
--   enabled        软关闭（不删除）
--   description    管理员备注

-- +goose Up

CREATE TABLE fingerprint_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    fields TEXT[] NOT NULL DEFAULT '{}',
    keyword VARCHAR(512) NOT NULL,
    case_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    description TEXT NOT NULL DEFAULT '',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,

    CONSTRAINT fp_rules_name_nonempty CHECK (length(trim(name)) > 0),
    CONSTRAINT fp_rules_keyword_nonempty CHECK (length(trim(keyword)) > 0)
);

-- 同 tenant 下 name 唯一（仅未软删行）
CREATE UNIQUE INDEX idx_fp_rules_tenant_name
    ON fingerprint_rules (tenant_id, name) WHERE deleted_at IS NULL;
-- match 路径查 enabled=true 的 tenant rule
CREATE INDEX idx_fp_rules_tenant_enabled
    ON fingerprint_rules (tenant_id) WHERE deleted_at IS NULL AND enabled = TRUE;

GRANT SELECT, INSERT, UPDATE, DELETE ON fingerprint_rules TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON fingerprint_rules TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS fingerprint_rules;
