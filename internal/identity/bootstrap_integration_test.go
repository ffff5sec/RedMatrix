//go:build integration

package identity

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

func setupRealRepo(t *testing.T) repo.Repository {
	t.Helper()
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, migrate.Up(ctx, db))

	pool, err := pgxpool.New(ctx, h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	return repo.NewPG(pool)
}

// === 跑两次 Bootstrap ===

func TestBootstrap_RealPG_CreatesAndIsIdempotent(t *testing.T) {
	r := setupRealRepo(t)
	ctx := context.Background()

	cfg := BootstrapConfig{
		Username: "admin",
		Email:    "admin@example.com",
		Password: "InitialBootstrapPwd1!",
	}

	// 第一次：创建
	res, err := Bootstrap(ctx, r, cfg)
	require.NoError(t, err)
	require.True(t, res.Created)

	// 验证库里有 SuperAdmin
	got, err := r.GetByUsername(ctx, "admin")
	require.NoError(t, err)
	assert.Equal(t, domain.RoleSuperAdmin, got.Role)
	assert.True(t, got.MustChangePassword)
	assert.Empty(t, got.TenantID)
	ok, _ := domain.VerifyPassword(cfg.Password, got.PasswordHash)
	assert.True(t, ok)

	// 第二次：跳过
	res, err = Bootstrap(ctx, r, cfg)
	require.NoError(t, err)
	assert.False(t, res.Created)

	// 仍只有一个 SuperAdmin
	n, err := r.CountByRole(ctx, domain.RoleSuperAdmin)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// === 随机密码可用 ===

func TestBootstrap_RealPG_RandomPasswordWorks(t *testing.T) {
	r := setupRealRepo(t)
	ctx := context.Background()

	cfg := BootstrapConfig{
		Username: "admin",
		Email:    "admin@example.com",
		// Password 留空 → 随机
	}

	res, err := Bootstrap(ctx, r, cfg)
	require.NoError(t, err)
	require.True(t, res.Created)
	require.Len(t, res.GeneratedPassword, randomBootstrapPasswordLen)

	got, err := r.GetByUsername(ctx, "admin")
	require.NoError(t, err)
	ok, _ := domain.VerifyPassword(res.GeneratedPassword, got.PasswordHash)
	assert.True(t, ok, "随机生成的密码必须能登录")
}

// === CountByRole 单独覆盖 ===

func TestRepo_CountByRole_ZeroAndAfterCreate(t *testing.T) {
	r := setupRealRepo(t)
	ctx := context.Background()

	n, err := r.CountByRole(ctx, domain.RoleSuperAdmin)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// 创建一个 SuperAdmin
	hash, err := domain.HashPassword("AnyValidPwd123!")
	require.NoError(t, err)
	require.NoError(t, r.Create(ctx, &domain.User{
		Username:     "sa1",
		Email:        "sa1@example.com",
		PasswordHash: hash,
		Role:         domain.RoleSuperAdmin,
		Status:       domain.StatusActive,
	}))

	n, err = r.CountByRole(ctx, domain.RoleSuperAdmin)
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	// 其他角色应为 0
	n, err = r.CountByRole(ctx, domain.RoleProjectAdmin)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}
