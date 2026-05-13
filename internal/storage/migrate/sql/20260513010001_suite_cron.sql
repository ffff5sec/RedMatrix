-- PR-S30：扫描套件 cron 调度。
--
-- 设计：
--   - scan_suites 加 schedule_kind / cron_expr / default_targets
--   - schedule_kind='immediate'（默认）= 仅手动 RunSuite 触发
--   - schedule_kind='cron' = 周期触发 RunSuite(default_targets)；scheduler 启动期 LoadAll
--
-- 与 scan_tasks 的 cron（PR-S12）独立：suite cron 触发整链（PR-S27 chaining），
-- task cron 触发单 task。两套模板互不干扰。

-- +goose Up

ALTER TABLE scan_suites
    ADD COLUMN schedule_kind VARCHAR(16) NOT NULL DEFAULT 'immediate',
    ADD COLUMN cron_expr VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN default_targets TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE scan_suites
    ADD CONSTRAINT suite_schedule_kind_valid
        CHECK (schedule_kind IN ('immediate', 'cron')),
    ADD CONSTRAINT suite_cron_requires_expr
        CHECK (
            schedule_kind <> 'cron'
            OR (length(trim(cron_expr)) > 0 AND array_length(default_targets, 1) >= 1)
        );

CREATE INDEX idx_scan_suites_cron
    ON scan_suites (schedule_kind)
    WHERE schedule_kind = 'cron' AND deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_scan_suites_cron;
ALTER TABLE scan_suites
    DROP CONSTRAINT IF EXISTS suite_cron_requires_expr,
    DROP CONSTRAINT IF EXISTS suite_schedule_kind_valid;
ALTER TABLE scan_suites
    DROP COLUMN IF EXISTS default_targets,
    DROP COLUMN IF EXISTS cron_expr,
    DROP COLUMN IF EXISTS schedule_kind;
