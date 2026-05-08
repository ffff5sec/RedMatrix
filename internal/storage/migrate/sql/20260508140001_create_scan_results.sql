-- 创建 scan_results 表（PR-S5 扫描结果落地）。
--
-- MVP 范围：每个 assignment 完成时上报 1+ 行 result（每行一条发现，如端口/URL/指纹）。
-- 数据存 JSONB 让前端按 task.kind 渲染；不在 schema 强约束 schema 演进。
--
-- 后续 PR：
--   PR-S6 ES 索引（scan_results 双写或 outbox 流转）
--   PR-S7 结果聚合（按 host/port/CVE 去重）
--
-- 字段：
--   id              UUID PK
--   task_id         UUID FK scan_tasks CASCADE
--   assignment_id   UUID FK scan_task_assignments CASCADE（结果归属 assignment 才能审计哪个 node 报的）
--   node_id         UUID FK nodes CASCADE（冗余，加快"按 node 查"）
--   kind            VARCHAR(32) 与 scan_tasks.kind 同（port_scan / web_crawl / ...）
--   data            JSONB 结果 payload；按 kind 不同 schema 不同
--   created_at      TIMESTAMPTZ
--
-- 索引：
--   idx(task_id, created_at) — 详情页 ListByTask
--   idx(assignment_id) — 审计单条 assignment 的全部结果
--   idx(node_id, created_at) — 后续按节点产出量统计

-- +goose Up

CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    assignment_id UUID NOT NULL REFERENCES scan_task_assignments(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind VARCHAR(32) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT scan_results_kind_valid CHECK (kind IN
        ('port_scan', 'web_crawl', 'subdomain', 'fingerprint')),
    CONSTRAINT scan_results_data_is_object CHECK (jsonb_typeof(data) = 'object')
);

CREATE INDEX idx_scan_results_task ON scan_results (task_id, created_at);
CREATE INDEX idx_scan_results_assignment ON scan_results (assignment_id);
CREATE INDEX idx_scan_results_node ON scan_results (node_id, created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_results TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON scan_results TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS scan_results;
