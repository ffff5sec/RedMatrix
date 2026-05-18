-- scan_tasks 加 continuous 模式字段（PR-S76 SPEC §2.6）。
--
-- 设计：
--   continuous_after_hours INT NULL    任务终态后等 N 小时自动 clone immediate 实例
--   next_continuous_at TIMESTAMPTZ NULL sweeper 拉 due 行的判定字段
--
-- 状态机：
--   1. 任务终态 + continuous_after_hours > 0 → service 设 next_continuous_at = FinishedAt + N
--   2. sweeper 每分钟拉 next_continuous_at ≤ now → 创新 immediate clone（继承
--      continuous_after_hours 让循环持续）→ 清原 task 的 next_continuous_at
--   3. clone 也终态时回到步骤 1，循环

-- +goose Up

ALTER TABLE scan_tasks
    ADD COLUMN continuous_after_hours INTEGER,
    ADD COLUMN next_continuous_at TIMESTAMPTZ;

-- sweeper 拉 due 行专用 partial index：仅含正在等待 trigger 的行
CREATE INDEX idx_scan_tasks_continuous_due
    ON scan_tasks (next_continuous_at)
    WHERE next_continuous_at IS NOT NULL AND deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_scan_tasks_continuous_due;
ALTER TABLE scan_tasks
    DROP COLUMN IF EXISTS next_continuous_at,
    DROP COLUMN IF EXISTS continuous_after_hours;
