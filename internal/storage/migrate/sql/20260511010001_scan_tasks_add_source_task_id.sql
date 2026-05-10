-- PR-S15：scan_tasks 加 source_task_id 自引用列。
--
-- 用途：cron 模板触发的 immediate 实例 / RetryTask 重派的实例，把
-- source_task_id 指回原 task 模板，UI 详情页可显示「来自：模板/重试自 X」。
--
-- ON DELETE SET NULL：模板被软删 / 物理删时，instance 仍可见，链接断开即可。

-- +goose Up

ALTER TABLE scan_tasks
    ADD COLUMN source_task_id UUID REFERENCES scan_tasks(id) ON DELETE SET NULL;

CREATE INDEX idx_scan_tasks_source ON scan_tasks (source_task_id)
    WHERE source_task_id IS NOT NULL;

-- +goose Down

DROP INDEX IF EXISTS idx_scan_tasks_source;
ALTER TABLE scan_tasks DROP COLUMN IF EXISTS source_task_id;
