-- PR-S18-B：assets.value UNIQUE 索引改 hash 化，避 btree 行 size 上限。
--
-- 背景：原 UNIQUE(tenant_id, project_id, kind, value) 索引行包含整个 value
-- 字串；当 value 是长 URL（接近 VARCHAR(2048) 上限）时，三个 UUID×16B +
-- value 2048B 已逼近 PG btree 单行 ~2700 字节硬上限，INSERT 直接 ERROR
-- "index row size exceeds maximum"。
--
-- 修法：加 value_sha256 BYTEA 列（CREATE/UPDATE 由 trigger 维护），UNIQUE
-- 索引建在 (tenant, project, kind, value_sha256) 上 — 4 个固定大小列，行
-- size 恒定 < 100 字节。原 value 仍可全文取出做 UI 显示。
--
-- 兼容：在线 ADD COLUMN + 函数式索引前需要回填一次（DO block），新行通过
-- BEFORE INSERT/UPDATE trigger 自动同步；老代码继续 INSERT value 不感知。

-- +goose Up

-- 1. 加新列（NULL 允许，回填后 SET NOT NULL）
ALTER TABLE assets ADD COLUMN IF NOT EXISTS value_sha256 BYTEA;

-- 2. 回填存量行的 sha256
UPDATE assets SET value_sha256 = digest(value, 'sha256') WHERE value_sha256 IS NULL;

-- 3. NOT NULL 约束
ALTER TABLE assets ALTER COLUMN value_sha256 SET NOT NULL;

-- 4. 替换 UNIQUE 索引
DROP INDEX IF EXISTS idx_assets_unique;
CREATE UNIQUE INDEX idx_assets_unique_hash ON assets (tenant_id, project_id, kind, value_sha256);

-- 5. trigger 自动维护 value_sha256（与 value 同步写）
-- 用 goose StatementBegin/End 标记 plpgsql 块（含 $$ 引号 + 多行）
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION assets_sync_value_sha256() RETURNS TRIGGER AS $$
BEGIN
    NEW.value_sha256 := digest(NEW.value, 'sha256');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS trg_assets_sync_sha256 ON assets;
CREATE TRIGGER trg_assets_sync_sha256
BEFORE INSERT OR UPDATE OF value ON assets
FOR EACH ROW EXECUTE FUNCTION assets_sync_value_sha256();

-- +goose Down

DROP TRIGGER IF EXISTS trg_assets_sync_sha256 ON assets;
DROP FUNCTION IF EXISTS assets_sync_value_sha256();
DROP INDEX IF EXISTS idx_assets_unique_hash;
CREATE UNIQUE INDEX idx_assets_unique ON assets (tenant_id, project_id, kind, value);
ALTER TABLE assets DROP COLUMN IF EXISTS value_sha256;
