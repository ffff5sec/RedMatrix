-- 创建 project_members 表（LLD 11 §3.3 / §5）。
--
-- ProjectMember 是用户加入项目的关联表。MVP 仅 ProjectAdmin 角色可作为成员
-- （SuperAdmin / TenantAuditor 不需要 —— 他们跨项目可见；schema 不强制角色，
-- service 层校验，schema 演进留弹性）。
--
-- 字段：
--   project_id  UUID FK → projects(id) ON DELETE CASCADE（项目删 → 成员清）
--   user_id     UUID FK → users(id) ON DELETE CASCADE（用户删 → 自动退）
--   tenant_id   UUID FK → accounts(id) ON DELETE CASCADE
--               冗余存储让查询免 join；与 project.tenant_id 必一致（应用层 + 写入校验）
--   added_by    UUID nullable —— SuperAdmin user_id；用户软删后保留以便审计
--   added_at    时间戳
--
-- 复合主键 (project_id, user_id) —— 同一用户同一项目只允许一行。

-- +goose Up

CREATE TABLE project_members (
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    tenant_id  UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,

    added_by UUID,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (project_id, user_id)
);

CREATE INDEX idx_project_members_user ON project_members (user_id);
CREATE INDEX idx_project_members_tenant ON project_members (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON project_members TO redmatrix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON project_members TO redmatrix_maintenance;

-- +goose Down

DROP TABLE IF EXISTS project_members;
