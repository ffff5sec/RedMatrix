-- PR-S27：套件 kind 间数据流（chaining）。
--
-- scan_suite_runs 加 current_step：当前正在执行的 kind 索引（基于 suite.kinds[]）。
-- 0 = 第一个 kind 正在跑；len(kinds) = 全部跑完；负数 = 链未启动（保留）。
--
-- RunSuite 改造：只创建第 1 个 step 的 task，等 task terminal 后由
-- aggregateSuiteRunStatus 触发 extractor → 创建下一 step。

-- +goose Up

ALTER TABLE scan_suite_runs
  ADD COLUMN current_step INT NOT NULL DEFAULT 0;

CREATE INDEX idx_scan_suite_runs_active_step
  ON scan_suite_runs (status, current_step) WHERE status IN ('pending', 'running');

-- +goose Down

DROP INDEX IF EXISTS idx_scan_suite_runs_active_step;
ALTER TABLE scan_suite_runs DROP COLUMN IF EXISTS current_step;
