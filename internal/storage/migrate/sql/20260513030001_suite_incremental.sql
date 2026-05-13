-- PR-S34：扫描套件增量模式。
--
-- 当 incremental=TRUE 且 schedule_kind='cron' 时，TriggerCronSuite 不用 default_targets，
-- 而是查 project 内 last_seen < now - incremental_stale_days 的 asset 作为 targets。
-- 空时本轮 skip，下一周期重试。

-- +goose Up

ALTER TABLE scan_suites
    ADD COLUMN incremental BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN incremental_stale_days INT NOT NULL DEFAULT 7;

ALTER TABLE scan_suites
    ADD CONSTRAINT suite_stale_days_pos CHECK (incremental_stale_days >= 1);

-- +goose Down

ALTER TABLE scan_suites
    DROP CONSTRAINT IF EXISTS suite_stale_days_pos;
ALTER TABLE scan_suites
    DROP COLUMN IF EXISTS incremental_stale_days,
    DROP COLUMN IF EXISTS incremental;
