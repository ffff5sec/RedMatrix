//go:build integration

package repo

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

const tenantA = "11111111-1111-1111-1111-111111111111"

func setupRepo(t *testing.T) Repository {
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

	return NewPG(pool)
}

func newProjectAdmin(username string) *domain.User {
	plainHash, _ := domain.HashPassword("Pa$$w0rd1234")
	return &domain.User{
		TenantID:     tenantA,
		Username:     username,
		PasswordHash: plainHash,
		Email:        username + "@example.com",
		Role:         domain.RoleProjectAdmin,
		Status:       domain.StatusActive,
	}
}

func newSuperAdmin(username string) *domain.User {
	plainHash, _ := domain.HashPassword("Pa$$w0rd1234")
	return &domain.User{
		Username:     username,
		PasswordHash: plainHash,
		Email:        username + "@example.com",
		Role:         domain.RoleSuperAdmin,
		Status:       domain.StatusActive,
	}
}

// === Create ===

func TestCreate_Roundtrip(t *testing.T) {
	r := setupRepo(t)
	u := newProjectAdmin("alice")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, r.Create(ctx, u))
	assert.NotEmpty(t, u.ID, "Create 应回填 id")

	got, err := r.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.Username, got.Username)
	assert.Equal(t, u.PasswordHash, got.PasswordHash)
	assert.Equal(t, u.Email, got.Email)
	assert.Equal(t, u.Role, got.Role)
	assert.Equal(t, domain.StatusActive, got.Status)
	assert.Equal(t, tenantA, got.TenantID)
	assert.Equal(t, 0, got.TokenVersion)
	assert.False(t, got.MustChangePassword)
	assert.True(t, got.LastLoginAt.IsZero(), "新建未登录")
}

func TestCreate_SuperAdmin_NoTenant(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	u := newSuperAdmin("root")
	require.NoError(t, r.Create(ctx, u))

	got, err := r.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "", got.TenantID)
	assert.Equal(t, domain.RoleSuperAdmin, got.Role)
}

func TestCreate_DuplicateUsername(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	require.NoError(t, r.Create(ctx, newProjectAdmin("alice")))

	err := r.Create(ctx, newProjectAdmin("alice"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserUsernameExists, c)
}

func TestCreate_DomainValidationFailedShortCircuits(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	u := newProjectAdmin("BAD-CASE") // 大写不合法
	err := r.Create(ctx, u)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c, "大写 username 应在域内拦下")
}

// === GetBy ===

func TestGetByUsername_FoundAndNotFound(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	u := newProjectAdmin("bob")
	require.NoError(t, r.Create(ctx, u))

	got, err := r.GetByUsername(ctx, "bob")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	_, err = r.GetByUsername(ctx, "ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

func TestGetByID_NotFound(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	_, err := r.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

// === UpdatePassword ===

func TestUpdatePassword_BumpsTokenVersion(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	u := newProjectAdmin("alice")
	require.NoError(t, r.Create(ctx, u))

	newHash, _ := domain.HashPassword("BrandN3w!")
	require.NoError(t, r.UpdatePassword(ctx, u.ID, newHash, false))

	got, err := r.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, newHash, got.PasswordHash)
	assert.Equal(t, 1, got.TokenVersion, "改密自动 token_version++")
	assert.False(t, got.MustChangePassword)
}

func TestUpdatePassword_MustChangeFlag(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	u := newProjectAdmin("alice")
	require.NoError(t, r.Create(ctx, u))

	newHash, _ := domain.HashPassword("Bootstrap!")
	require.NoError(t, r.UpdatePassword(ctx, u.ID, newHash, true))

	got, err := r.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, got.MustChangePassword)
}

func TestUpdatePassword_NotFound(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	err := r.UpdatePassword(ctx, "00000000-0000-0000-0000-000000000000", "x", false)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

// === IncrementTokenVersion ===

func TestIncrementTokenVersion(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	u := newProjectAdmin("alice")
	require.NoError(t, r.Create(ctx, u))

	for i := 1; i <= 3; i++ {
		require.NoError(t, r.IncrementTokenVersion(ctx, u.ID))
	}
	got, _ := r.GetByID(ctx, u.ID)
	assert.Equal(t, 3, got.TokenVersion)
}

// === LogoutAllSessions: 验证单事务内 tv++ + sessions 全部 expires_at=now() ===

func TestLogoutAllSessions_Atomic(t *testing.T) {
	users, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	// 三条未过期 session
	for i := 0; i < 3; i++ {
		require.NoError(t, sessions.Create(ctx, newSession(u.ID, u.TenantID)))
	}

	require.NoError(t, users.LogoutAllSessions(ctx, u.ID))

	got, _ := users.GetByID(ctx, u.ID)
	assert.Equal(t, 1, got.TokenVersion, "tv 应+1")

	now := time.Now().UTC()
	rows, err := sessions.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	for _, s := range rows {
		assert.True(t, s.IsExpired(now), "所有 session 应被置过期")
	}
}

func TestLogoutAllSessions_NotFound(t *testing.T) {
	r := setupRepo(t)
	err := r.LogoutAllSessions(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

// === UpdateLastLogin ===

func TestUpdateLastLogin(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	u := newProjectAdmin("alice")
	require.NoError(t, r.Create(ctx, u))
	assert.True(t, u.LastLoginAt.IsZero())

	require.NoError(t, r.UpdateLastLogin(ctx, u.ID))

	got, _ := r.GetByID(ctx, u.ID)
	assert.False(t, got.LastLoginAt.IsZero())
	assert.WithinDuration(t, time.Now(), got.LastLoginAt, 5*time.Second)
}

// === UpdateStatus ===

func TestUpdateStatus(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	u := newProjectAdmin("alice")
	require.NoError(t, r.Create(ctx, u))

	require.NoError(t, r.UpdateStatus(ctx, u.ID, domain.StatusDisabled))
	got, _ := r.GetByID(ctx, u.ID)
	assert.Equal(t, domain.StatusDisabled, got.Status)

	require.NoError(t, r.UpdateStatus(ctx, u.ID, domain.StatusPendingDeletion))
	got, _ = r.GetByID(ctx, u.ID)
	assert.Equal(t, domain.StatusPendingDeletion, got.Status)
}

func TestUpdateStatus_InvalidValue(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	err := r.UpdateStatus(ctx, "00000000-0000-0000-0000-000000000000", domain.Status("BOGUS"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === PG CHECK 约束兜底（应用层逃逸）===
//
// 应用层 ValidateTenantConsistency 已挡，但若有人 bypass（直接 SQL）DB 层
// CHECK 也应阻止。集成测试故意用空 ID + 不合法 role 触发 PG。

// === Roundtrip 同 ID 不重复 ===

func TestCreate_MultiUsersUniqueID(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	ids := map[string]bool{}
	for i := 0; i < 5; i++ {
		u := newProjectAdmin("user_" + string(rune('a'+i)))
		require.NoError(t, r.Create(ctx, u))
		assert.False(t, ids[u.ID], "ID 应全局唯一")
		ids[u.ID] = true
	}
}

// === List ===

func TestList_FilterByStatusAndRole(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	// 3 PA active + 1 SA + 1 PA disabled
	for _, n := range []string{"alice", "bob", "carol"} {
		require.NoError(t, r.Create(ctx, newProjectAdmin(n)))
	}
	require.NoError(t, r.Create(ctx, newSuperAdmin("root")))
	dis := newProjectAdmin("dave")
	dis.Status = domain.StatusDisabled
	require.NoError(t, r.Create(ctx, dis))

	got, total, err := r.List(ctx,
		ListFilter{Status: domain.StatusActive, Role: domain.RoleProjectAdmin},
		Page{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "active + ProjectAdmin = 3")
	assert.Len(t, got, 3)
	for _, u := range got {
		assert.Equal(t, domain.RoleProjectAdmin, u.Role)
		assert.Equal(t, domain.StatusActive, u.Status)
	}
}

func TestList_KeywordILIKE(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	require.NoError(t, r.Create(ctx, newProjectAdmin("alice_dev")))
	require.NoError(t, r.Create(ctx, newProjectAdmin("bob_qa")))
	require.NoError(t, r.Create(ctx, newProjectAdmin("alicia_devops")))

	got, total, err := r.List(ctx,
		ListFilter{Keyword: "ali"},
		Page{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "ali → alice_dev + alicia_devops")
	assert.Len(t, got, 2)
}

func TestList_Pagination(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()

	for i := 0; i < 12; i++ {
		require.NoError(t, r.Create(ctx, newProjectAdmin("user_"+string(rune('a'+i)))))
	}

	page1, total, err := r.List(ctx, ListFilter{}, Page{Page: 1, PageSize: 5})
	require.NoError(t, err)
	assert.Equal(t, 12, total)
	require.Len(t, page1, 5)

	page3, _, err := r.List(ctx, ListFilter{}, Page{Page: 3, PageSize: 5})
	require.NoError(t, err)
	require.Len(t, page3, 2, "12 行 / 5 大小 → 第 3 页 2 条")
}

func TestList_Empty(t *testing.T) {
	r := setupRepo(t)
	got, total, err := r.List(context.Background(), ListFilter{},
		Page{Page: 1, PageSize: 10})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, got)
}

// === UpdateEmail ===

func TestUpdateEmail_RoundTrip(t *testing.T) {
	r := setupRepo(t)
	ctx := context.Background()
	u := newProjectAdmin("eve")
	require.NoError(t, r.Create(ctx, u))

	require.NoError(t, r.UpdateEmail(ctx, u.ID, "eve@example.org"))

	got, err := r.GetByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "eve@example.org", got.Email)
}

func TestUpdateEmail_NotFound(t *testing.T) {
	r := setupRepo(t)
	err := r.UpdateEmail(context.Background(),
		"00000000-0000-0000-0000-000000000000", "nope@example.com")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}
