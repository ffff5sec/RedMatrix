//go:build integration

package migrate

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

// === 全量迁移：Up 应用所有 + 验证副产物落库 ===

func TestUp_AppliesAllMigrations(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, Up(ctx, db))

	// 版本号应非 0
	v, err := Version(ctx, db)
	require.NoError(t, err)
	assert.Greater(t, v, int64(0), "Up 后版本号必须 > 0")

	// 0001：role 必须存在
	for _, role := range []string{"redmatrix_app", "redmatrix_maintenance"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role,
		).Scan(&exists))
		assert.Truef(t, exists, "role %s 必须存在", role)
	}

	// 0002：扩展必须装上
	for _, ext := range []string{"pgcrypto", "pg_trgm", "pg_stat_statements"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = $1)`, ext,
		).Scan(&exists))
		assert.Truef(t, exists, "extension %s 必须已安装", ext)
	}
}

// === 幂等性：Up 多次执行不应出错 ===

func TestUp_Idempotent(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, Up(ctx, db))
	v1, err := Version(ctx, db)
	require.NoError(t, err)

	// 再跑一次，版本号不变（无未应用迁移）
	require.NoError(t, Up(ctx, db))
	v2, err := Version(ctx, db)
	require.NoError(t, err)

	assert.Equal(t, v1, v2, "二次 Up 不应改动版本号")
}

// === Status 不报错 ===

func TestStatus_RealPG(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Status 在未应用迁移前也应能返回（goose 自动建 schema_migrations）
	require.NoError(t, Status(ctx, db))

	// 应用后再次查询
	require.NoError(t, Up(ctx, db))
	require.NoError(t, Status(ctx, db))
}

// === Down：回滚最新迁移，版本号下降 ===

func TestDown_RollsBackOne(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, Up(ctx, db))
	vUp, err := Version(ctx, db)
	require.NoError(t, err)

	require.NoError(t, Down(ctx, db))
	vDown, err := Version(ctx, db)
	require.NoError(t, err)

	assert.Less(t, vDown, vUp, "Down 后版本号应下降")

	// 0004（最新）已被回滚 → users 表应不存在
	var hasUsers bool
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='users')`,
	).Scan(&hasUsers))
	assert.False(t, hasUsers, "Down 应移除 0004 创建的 users 表")
}

// 验证 0004 users 表 schema
func TestUp_UsersTableExists(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, Up(ctx, db))

	for _, col := range []string{"id", "tenant_id", "username", "password_hash",
		"email", "role", "status", "token_version", "must_change_password",
		"last_login_at", "created_at", "updated_at"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			                WHERE table_name='users' AND column_name=$1)`,
			col).Scan(&exists))
		assert.Truef(t, exists, "列 users.%s 应存在", col)
	}

	// CHECK 约束三件套
	for _, c := range []string{"users_role_valid", "users_status_valid",
		"users_tenant_role_consistency"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname=$1)`,
			c).Scan(&exists))
		assert.Truef(t, exists, "约束 %s 应存在", c)
	}
}

// 新增：验证 0003 outbox 表 schema 正确
func TestUp_OutboxTableExists(t *testing.T) {
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	require.NoError(t, Up(ctx, db))

	// 验证关键列与索引存在
	for _, col := range []string{"id", "topic", "payload", "tenant_id",
		"created_at", "next_attempt_at", "published_at", "failed_permanently_at",
		"attempts", "last_error", "trace_id"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.columns
			                WHERE table_name='outbox_events' AND column_name=$1)`,
			col).Scan(&exists))
		assert.Truef(t, exists, "列 outbox_events.%s 应存在", col)
	}

	for _, idx := range []string{"idx_outbox_pending", "idx_outbox_topic", "idx_outbox_tenant"} {
		var exists bool
		require.NoError(t, db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname=$1)`,
			idx).Scan(&exists))
		assert.Truef(t, exists, "索引 %s 应存在", idx)
	}
}
