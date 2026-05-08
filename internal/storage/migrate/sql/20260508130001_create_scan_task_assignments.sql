-- 创建 scan_task_assignments 表（PR-S2 调度派发）。
--
-- 一条 assignment = "某 task 派发给某 node" 的派发单。
-- task 创建时 service 同步派发：项目 allowed_nodes ∩ tenant 内 online 节点
-- → INSERT 多条 assignment，状态 'assigned'。
--
-- 后续 PR-S3：Agent.PullTasks 拉取自己的 assigned 行 → status='pulled'；
-- Agent.ReportTaskProgress 推 status 转移 + finished_at + error。
--
-- 字段：
--   id              UUID PK
--   task_id         UUID FK scan_tasks CASCADE
--   node_id         UUID FK nodes CASCADE
--   status          assigned / pulled / running / completed / failed
--   assigned_at     创建时间（默认 now()）
--   pulled_at       Agent 拉取时刻（PR-S3 写）
--   started_at      Agent 实际开跑时刻
--   finished_at     终态时刻
--   error           失败原因（仅 status=failed）
--
-- 索引：
--   uniq(task_id, node_id) — 一个 task 一个 node 一份
--   idx(node_id, status) WHERE status IN ('assigned', 'pulled') — Agent.PullTasks 主查询
--   idx(task_id) — 详情页 ListByTask

-- +goose Up

CREATE TABLE scan_task_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    status VARCHAR(20) NOT NULL DEFAULT 'assigned',

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    pulled_at   TIMESTAMPTZ,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error       TEXT,

    CONSTRAINT scan_task_assignments_status_valid CHECK (status IN
        ('assigned', 'pulled', 'running', 'completed', 'failed'))
);

CREATE UNIQUE INDEX scan_task_assignments_task_node_uniq
    ON scan_task_assignments (task_id, node_id);

CREATE INDEX idx_scan_task_assignments_node_pull
    ON scan_task_assignments (node_id, status)
    WHERE status IN ('assigned', 'pulled');

CREATE INDEX idx_scan_task_assignments_task
    ON scan_task_assignments (task_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_task_assignments TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_task_assignments TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS scan_task_assignments;
