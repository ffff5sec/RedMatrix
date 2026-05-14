-- 给 assets 加 disappeared_at 字段（PR-S59）。
--
-- 设计：
--   - disappeared_at IS NULL：资产"活着"（在阈值内被扫过）
--   - disappeared_at NOT NULL：sweeper 上次 SET 的时间；表示已派过 asset_disappeared 事件
--   - 资产"回归"（UPSERT 触发 last_seen 推进）时 disappeared_at 自动 reset 成 NULL，
--     让下次再消失能再派事件
--
-- 索引：单列 partial index 加速 sweeper 主查询
--   WHERE last_seen < $cutoff AND disappeared_at IS NULL

-- +goose Up

ALTER TABLE assets ADD COLUMN disappeared_at TIMESTAMPTZ;

CREATE INDEX idx_assets_alive_last_seen
    ON assets (last_seen)
    WHERE disappeared_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_assets_alive_last_seen;
ALTER TABLE assets DROP COLUMN IF EXISTS disappeared_at;
