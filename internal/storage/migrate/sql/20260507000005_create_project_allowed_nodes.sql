-- 创建 project_allowed_nodes 表（LLD 11 §3.4 / §6）。
--
-- 项目可指定可用节点白名单：
--   - 表中无 project_id 的行 → 该项目所有节点可用（隐含 ALL，默认）
--   - 表中有 project_id 的行 → 仅这些 node_id 对该项目可用
--
-- 复合主键 (project_id, node_id) — 同一节点对同一项目至多 1 行。
--
-- 索引：
--   PK 自动 covering(project_id, node_id) — 满足 IsNodeAllowed 单点查询
--   反向 idx(node_id) — 删 node 时 cascade 走主键索引；显式索引用于按节点反查项目

-- +goose Up

CREATE TABLE project_allowed_nodes (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    node_id    UUID NOT NULL REFERENCES nodes(id)    ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by   UUID,

    PRIMARY KEY (project_id, node_id)
);

CREATE INDEX idx_project_allowed_nodes_node ON project_allowed_nodes (node_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON project_allowed_nodes TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON project_allowed_nodes TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS project_allowed_nodes;
