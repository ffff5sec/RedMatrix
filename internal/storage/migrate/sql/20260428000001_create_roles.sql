-- 创建 RedMatrix 三个 PG 角色，与 docs/LLD/22-rls-implementation.md §4.4 +
-- docs/LLD/01-database-schema.md §1.1.3 对齐。
--
-- 角色分工：
--   redmatrix_admin        — DDL / 迁移（goose 用，仅 CI 与升级时连接）
--   redmatrix_maintenance  — 旁路 RLS（pg_partman_bgw / 跨租户运维 / 备份）
--   redmatrix_app          — 应用账号（受 RLS 强制约束，HLD §7）
--
-- 密码注入：本迁移不写明文密码（防止入仓）。部署后由运维通过
--   ALTER ROLE redmatrix_app PASSWORD '...';
-- 注入。具体流程见 docs/LLD/40-deployment-detail.md §4.1.1。
--
-- 注意：本迁移须由 PG 超管（如 postgres）账号执行；redmatrix_admin 自身
-- 由本迁移之外的 docker entrypoint 创建（见 40 §2.2）。

-- +goose Up

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'redmatrix_app') THEN
        CREATE ROLE redmatrix_app WITH LOGIN;
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'redmatrix_maintenance') THEN
        CREATE ROLE redmatrix_maintenance WITH LOGIN;
    END IF;
END
$$;
-- +goose StatementEnd

-- 默认权限：未来在 schema public 下创建的表 / 序列自动赋权。
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO redmatrix_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO redmatrix_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES TO redmatrix_maintenance;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO redmatrix_maintenance;

GRANT USAGE ON SCHEMA public TO redmatrix_app, redmatrix_maintenance;

-- +goose Down

-- 注：DROP ROLE 仅在所有依赖对象（拥有的表、授权）清理后才能执行。
-- 若需完整回滚，先回滚后续迁移（goose down 多次），再手工 DROP ROLE。
-- 本步骤仅撤销默认权限和 schema 使用权。
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON TABLES FROM redmatrix_app, redmatrix_maintenance;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE ALL ON SEQUENCES FROM redmatrix_app, redmatrix_maintenance;

REVOKE USAGE ON SCHEMA public FROM redmatrix_app, redmatrix_maintenance;
