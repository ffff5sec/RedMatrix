//go:build integration

package repo

import (
	"context"
	"database/sql"
	"net/netip"
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

// setupSessionRepo 装好 user repo + session repo + 一个新建的 user（session 必须 FK）。
func setupSessionRepo(t *testing.T) (Repository, SessionRepository, *domain.User) {
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

	users := NewPG(pool)
	sessions := NewSessionPG(pool)

	u := newProjectAdmin("session_owner")
	require.NoError(t, users.Create(ctx, u))
	return users, sessions, u
}

func newSession(userID, tenantID string) *domain.Session {
	now := time.Now().UTC()
	return &domain.Session{
		TenantID:     tenantID,
		UserID:       userID,
		UserAgent:    "go-test/1.0",
		IP:           netip.MustParseAddr("203.0.113.42"),
		IssuedAt:     now,
		LastSeenAt:   now,
		TokenVersion: 0,
		ExpiresAt:    now.Add(12 * time.Hour),
	}
}

// === Create ===

func TestSession_Create_Roundtrip(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession(u.ID, u.TenantID)
	require.NoError(t, sessions.Create(ctx, s))
	assert.NotEmpty(t, s.ID, "Create 应回填 id")

	got, err := sessions.GetByID(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, s.ID, got.ID)
	assert.Equal(t, u.ID, got.UserID)
	assert.Equal(t, u.TenantID, got.TenantID)
	assert.Equal(t, "go-test/1.0", got.UserAgent)
	assert.Equal(t, "203.0.113.42", got.IP.String())
	assert.Equal(t, 0, got.TokenVersion)
	assert.False(t, got.ExpiresAt.IsZero())
}

func TestSession_Create_NullableIP(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession(u.ID, u.TenantID)
	s.IP = netip.Addr{} // 零值
	require.NoError(t, sessions.Create(ctx, s))

	got, err := sessions.GetByID(ctx, s.ID)
	require.NoError(t, err)
	assert.False(t, got.IP.IsValid(), "零值 IP 应保持零值")
}

func TestSession_Create_NullableTenant(t *testing.T) {
	users, sessions, _ := setupSessionRepo(t)
	ctx := context.Background()

	// 跨租户 SuperAdmin 的 session
	su := newSuperAdmin("super1")
	require.NoError(t, users.Create(ctx, su))

	s := newSession(su.ID, "")
	require.NoError(t, sessions.Create(ctx, s))

	got, err := sessions.GetByID(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, "", got.TenantID, "SuperAdmin tenant_id 必须空")
}

func TestSession_Create_RejectsBadDomain(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession(u.ID, u.TenantID)
	s.ExpiresAt = s.IssuedAt // expires_at 不大于 issued_at → 域内拦下
	err := sessions.Create(ctx, s)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestSession_Create_FK(t *testing.T) {
	_, sessions, _ := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession("00000000-0000-0000-0000-000000000000", "")
	err := sessions.Create(ctx, s)
	require.Error(t, err, "user 不存在 → FK 违反")
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

// === GetByID ===

func TestSession_GetByID_NotFound(t *testing.T) {
	_, sessions, _ := setupSessionRepo(t)
	_, err := sessions.GetByID(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrSessionNotFound, c)
}

// === ListByUser ===

func TestSession_ListByUser_OrderByExpiresDesc(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i, dur := range []time.Duration{1 * time.Hour, 8 * time.Hour, 24 * time.Hour} {
		s := newSession(u.ID, u.TenantID)
		s.IssuedAt = now.Add(time.Duration(i) * time.Second)
		s.LastSeenAt = s.IssuedAt
		s.ExpiresAt = s.IssuedAt.Add(dur)
		require.NoError(t, sessions.Create(ctx, s))
	}

	got, err := sessions.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// 应按 expires_at DESC：24h > 8h > 1h
	assert.True(t, got[0].ExpiresAt.After(got[1].ExpiresAt))
	assert.True(t, got[1].ExpiresAt.After(got[2].ExpiresAt))
}

func TestSession_ListByUser_Empty(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	got, err := sessions.ListByUser(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// === Delete ===

func TestSession_Delete(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession(u.ID, u.TenantID)
	require.NoError(t, sessions.Create(ctx, s))

	require.NoError(t, sessions.Delete(ctx, s.ID))

	_, err := sessions.GetByID(ctx, s.ID)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrSessionNotFound, c)
}

func TestSession_Delete_NotFound(t *testing.T) {
	_, sessions, _ := setupSessionRepo(t)
	err := sessions.Delete(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrSessionNotFound, c)
}

// === ExpireAllByUser ===

func TestSession_ExpireAllByUser(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	// 三条未过期 session
	for i := 0; i < 3; i++ {
		require.NoError(t, sessions.Create(ctx, newSession(u.ID, u.TenantID)))
	}

	require.NoError(t, sessions.ExpireAllByUser(ctx, u.ID))

	got, err := sessions.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	now := time.Now().UTC()
	for _, s := range got {
		assert.True(t, s.IsExpired(now), "ExpireAll 后所有 session 都应过期")
	}
}

func TestSession_ExpireAllByUser_NoSessions(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	require.NoError(t, sessions.ExpireAllByUser(context.Background(), u.ID))
}

// === UpdateLastSeen ===

func TestSession_UpdateLastSeen(t *testing.T) {
	_, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	s := newSession(u.ID, u.TenantID)
	// 故意把 last_seen_at 调到过去
	s.LastSeenAt = s.LastSeenAt.Add(-time.Hour)
	require.NoError(t, sessions.Create(ctx, s))

	require.NoError(t, sessions.UpdateLastSeen(ctx, s.ID))

	got, err := sessions.GetByID(ctx, s.ID)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now(), got.LastSeenAt, 5*time.Second)
}

func TestSession_UpdateLastSeen_NotFound(t *testing.T) {
	_, sessions, _ := setupSessionRepo(t)
	err := sessions.UpdateLastSeen(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrSessionNotFound, c)
}

// === FK CASCADE：user 删，session 自动删 ===

func TestSession_CascadesOnUserDelete(t *testing.T) {
	users, sessions, u := setupSessionRepo(t)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		require.NoError(t, sessions.Create(ctx, newSession(u.ID, u.TenantID)))
	}

	// 直接 SQL 删用户（repo 没有 Delete API；用 pgxpool 直接 Exec）
	pool := users.(*pgRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID)
	require.NoError(t, err)

	got, err := sessions.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, got, "ON DELETE CASCADE 应级联删除 session")
}
