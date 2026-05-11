-- PR-S22-A：scan_tasks + scan_task_assignments 加 targets text[] 支持批量目标。
--
-- 设计：
--   - scan_tasks.targets text[] — 用户输入 N 个 target（host/ip/url 混排）
--   - scan_task_assignments.targets text[] — dispatch 时把任务级 N targets
--     按 online node 数平均切片到每个 assignment
--   - 老 target 字段保留兼容；migration 把存量 target 回填到 targets[0]
--   - NOT NULL DEFAULT '{}' 让旧代码 INSERT 不显式传不破

-- +goose Up

ALTER TABLE scan_tasks ADD COLUMN IF NOT EXISTS targets TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE scan_task_assignments ADD COLUMN IF NOT EXISTS targets TEXT[] NOT NULL DEFAULT '{}';

-- 存量行回填：targets 仍空时取 target 列填入
UPDATE scan_tasks
SET targets = ARRAY[target]
WHERE (targets IS NULL OR cardinality(targets) = 0)
  AND target IS NOT NULL
  AND target <> '';

-- 注：assignments 不存 target（只关联 task）；新列默认空数组即可，
-- 旧 assignment 由 service 端 dispatch 时不会用到 targets（agent 仍读 task.target）。

-- +goose Down

ALTER TABLE scan_tasks DROP COLUMN IF EXISTS targets;
ALTER TABLE scan_task_assignments DROP COLUMN IF EXISTS targets;
