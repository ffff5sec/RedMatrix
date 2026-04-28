-- 安装 RedMatrix 必需的 PG 扩展，与 docs/LLD/40-deployment-detail.md §4.1.1 对齐。
--
-- 本迁移仅安装"PG 标准镜像即可用"的扩展：
--   pgcrypto              — gen_random_uuid() / digest()
--   pg_trgm               — 资产域名 / URL 模糊搜索（trigram GIN 索引）
--   pg_stat_statements    — 慢查询统计（生产观测）
--
-- pg_partman 的安装迁移在拉起带定制镜像的 PG 后单独提交（依赖
-- shared_preload_libraries=pg_partman_bgw 在 PG 启动参数中设置）。
-- 见 docs/LLD/01-database-schema.md §1.3.3。

-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- +goose Down
DROP EXTENSION IF EXISTS pg_stat_statements;
DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS pgcrypto;
