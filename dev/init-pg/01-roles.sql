-- 开发档：在 postgres 容器首启时建好 RedMatrix 角色 + 设密码。
--
-- 生产档：迁移 0001 创建 role（无密码），密码由运维 ALTER ROLE 注入
-- （40 §4.1.1）。本文件仅 docker-compose dev 路径用。
--
-- 与 .env.dev 的密码对齐。

CREATE ROLE redmatrix_app WITH LOGIN PASSWORD 'appdev';
CREATE ROLE redmatrix_maintenance WITH LOGIN PASSWORD 'maintdev';

GRANT USAGE ON SCHEMA public TO redmatrix_app, redmatrix_maintenance;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO redmatrix_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO redmatrix_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON TABLES TO redmatrix_maintenance;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT ALL ON SEQUENCES TO redmatrix_maintenance;
