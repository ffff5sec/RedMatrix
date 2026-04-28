// Package migrate 包装 pressly/goose 提供 PG schema 迁移能力。
//
// 设计原则（docs/LLD/00-conventions.md §5.3 + 40 §8.5）：
//   - 迁移 SQL 嵌入二进制（embed.FS），无需挂载文件 / 额外工具
//   - 仅 forward-only：已落库迁移不修改；新增即追加新 timestamp 文件
//   - 每个迁移必须含 +goose Up / +goose Down 标记（即使 Down 是 no-op）
//
// 用法（cmd/server boot 序列）：
//
//	db, err := sql.Open("pgx", cfg.DB.PGAdminDSN)
//	if err := migrate.Up(ctx, db); err != nil { ... }
//
// 注意：Up 必须用具备 DDL 权限的账号（redmatrix_admin 或超管）连接；
// redmatrix_app 仅有 DML 权限，不能跑迁移。详见 22-rls §4.4 + 40 D40-07。
package migrate

import (
	"context"
	"database/sql"
	"embed"

	"github.com/pressly/goose/v3"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

//go:embed sql/*.sql
var sqlFS embed.FS

const (
	dialect = "postgres"
	sqlDir  = "sql"
)

// Up 应用所有未执行的迁移到最新版本。
func Up(ctx context.Context, db *sql.DB) error {
	if err := setup(); err != nil {
		return err
	}
	if err := goose.UpContext(ctx, db, sqlDir); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "PG 迁移 Up 失败")
	}
	return nil
}

// Status 把当前迁移状态打印到 goose 默认 stdout（运维诊断用）。
func Status(ctx context.Context, db *sql.DB) error {
	if err := setup(); err != nil {
		return err
	}
	if err := goose.StatusContext(ctx, db, sqlDir); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "PG 迁移 Status 失败")
	}
	return nil
}

// Down 回滚最新一次迁移。生产慎用（只读复盘 + 人工执行更安全）。
func Down(ctx context.Context, db *sql.DB) error {
	if err := setup(); err != nil {
		return err
	}
	if err := goose.DownContext(ctx, db, sqlDir); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "PG 迁移 Down 失败")
	}
	return nil
}

// Version 返回当前 schema 版本号（goose 内部 timestamp）。0 表示未应用任何迁移。
func Version(ctx context.Context, db *sql.DB) (int64, error) {
	if err := setup(); err != nil {
		return 0, err
	}
	v, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return 0, errx.Wrap(errx.ErrDatabase, err, "PG 迁移版本查询失败")
	}
	return v, nil
}

// FS 暴露 embed.FS 给调用方做静态扫描 / 测试。
func FS() embed.FS { return sqlFS }

// setup 初始化 goose 的全局 dialect / FS（goose v3 仍是全局状态）。幂等。
func setup() error {
	goose.SetBaseFS(sqlFS)
	if err := goose.SetDialect(dialect); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "goose dialect 配置失败")
	}
	return nil
}
