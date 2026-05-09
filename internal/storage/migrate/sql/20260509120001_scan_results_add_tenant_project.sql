-- PR-S7：scan_results 加 tenant_id / project_id 冗余列。
--
-- 动机：SearchResults RPC 需在 ES 端按 tenant / project 过滤（TA / PA 权限收紧）。
-- 这两个 ID 是 task 持有的，但跨 join 查询过慢；冗余进 result 行（写时一并写）
-- 让 ES 文档能直接 filter，索引体积上升 < 10%（两个 keyword）可接受。
--
-- 回填策略：现有表小（dev / 早期使用），ALTER 时直接从 task 反查回填，再加 NOT NULL。

-- +goose Up

ALTER TABLE scan_results
    ADD COLUMN tenant_id UUID,
    ADD COLUMN project_id UUID;

UPDATE scan_results r
SET tenant_id = t.tenant_id,
    project_id = t.project_id
FROM scan_tasks t
WHERE r.task_id = t.id;

ALTER TABLE scan_results
    ALTER COLUMN tenant_id SET NOT NULL,
    ALTER COLUMN project_id SET NOT NULL,
    ADD CONSTRAINT scan_results_tenant_fk FOREIGN KEY (tenant_id) REFERENCES accounts(id) ON DELETE CASCADE,
    ADD CONSTRAINT scan_results_project_fk FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;

CREATE INDEX idx_scan_results_tenant ON scan_results (tenant_id, created_at);
CREATE INDEX idx_scan_results_project ON scan_results (project_id, created_at);

-- +goose Down

DROP INDEX IF EXISTS idx_scan_results_project;
DROP INDEX IF EXISTS idx_scan_results_tenant;
ALTER TABLE scan_results
    DROP CONSTRAINT IF EXISTS scan_results_project_fk,
    DROP CONSTRAINT IF EXISTS scan_results_tenant_fk,
    DROP COLUMN IF EXISTS project_id,
    DROP COLUMN IF EXISTS tenant_id;
