//go:build integration

package repo

import (
	"context"
	"database/sql"
	"strings"
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

// setupAPIKeyRepo 装好 user repo + apikey repo + 一个新建的 user。
func setupAPIKeyRepo(t *testing.T) (Repository, APIKeyRepository, *domain.User) {
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
	keys := NewAPIKeyPG(pool)

	u := newProjectAdmin("apikey_owner")
	require.NoError(t, users.Create(ctx, u))
	return users, keys, u
}

func newAPIKey(userID, tenantID, prefix string) *domain.APIKey {
	return &domain.APIKey{
		TenantID:   tenantID,
		UserID:     userID,
		Name:       "ci-bot",
		KeyPrefix:  prefix,
		SecretHash: strings.Repeat("a", 64),
	}
}

// === Insert ===

func TestAPIKey_Insert_Roundtrip(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "ABCDEFGH")
	k.Scopes = []string{"scan:read", "asset:write"}
	require.NoError(t, keys.Insert(ctx, k))
	assert.NotEmpty(t, k.ID, "Insert 应回填 id")
	assert.False(t, k.CreatedAt.IsZero(), "Insert 应回填 created_at")

	got, err := keys.GetByID(ctx, k.ID)
	require.NoError(t, err)
	assert.Equal(t, k.ID, got.ID)
	assert.Equal(t, u.ID, got.UserID)
	assert.Equal(t, u.TenantID, got.TenantID)
	assert.Equal(t, "ci-bot", got.Name)
	assert.Equal(t, "ABCDEFGH", got.KeyPrefix)
	assert.Equal(t, []string{"scan:read", "asset:write"}, got.Scopes)
	assert.Nil(t, got.ExpiresAt)
	assert.Nil(t, got.LastUsedAt)
	assert.Nil(t, got.RevokedAt)
}

func TestAPIKey_Insert_DefaultEmptyScopes(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "EMPTY222")
	// 不设 Scopes，靠 default '[]'
	require.NoError(t, keys.Insert(ctx, k))

	got, err := keys.GetByID(ctx, k.ID)
	require.NoError(t, err)
	assert.Empty(t, got.Scopes)
}

func TestAPIKey_Insert_WithExpiresAt(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	exp := time.Now().UTC().Add(24 * time.Hour)
	k := newAPIKey(u.ID, u.TenantID, "EXP44444")
	k.ExpiresAt = &exp
	require.NoError(t, keys.Insert(ctx, k))

	got, err := keys.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.ExpiresAt)
	assert.WithinDuration(t, exp, *got.ExpiresAt, time.Second)
}

func TestAPIKey_Insert_PrefixUnique(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	require.NoError(t, keys.Insert(ctx, newAPIKey(u.ID, u.TenantID, "DUPE5555")))

	// 同 prefix 第二次应违 UNIQUE
	err := keys.Insert(ctx, newAPIKey(u.ID, u.TenantID, "DUPE5555"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c, "UNIQUE 冲突应返 ErrDatabase（caller 决定重试）")
}

func TestAPIKey_Insert_RejectsBadDomain(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "TOOLONGX") // 8 字符 OK，但改名
	k.Name = ""                                  // 空名 → 域内拦下
	err := keys.Insert(ctx, k)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestAPIKey_Insert_FK(t *testing.T) {
	_, keys, _ := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey("00000000-0000-0000-0000-000000000000", "", "ORPHAN23")
	err := keys.Insert(ctx, k)
	require.Error(t, err, "user 不存在 → FK 违反")
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

// === FindByPrefix ===

func TestAPIKey_FindByPrefix(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	require.NoError(t, keys.Insert(ctx, newAPIKey(u.ID, u.TenantID, "FINDME22")))

	got, err := keys.FindByPrefix(ctx, "FINDME22")
	require.NoError(t, err)
	assert.Equal(t, "FINDME22", got.KeyPrefix)
}

func TestAPIKey_FindByPrefix_NotFound(t *testing.T) {
	_, keys, _ := setupAPIKeyRepo(t)
	_, err := keys.FindByPrefix(context.Background(), "MISSING2")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
}

// === GetByID ===

func TestAPIKey_GetByID_NotFound(t *testing.T) {
	_, keys, _ := setupAPIKeyRepo(t)
	_, err := keys.GetByID(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
}

// === ListByUser ===

func TestAPIKey_ListByUser_OrderCreatedDesc(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	prefixes := []string{"AAAA2222", "BBBB3333", "CCCC4444"}
	for _, p := range prefixes {
		require.NoError(t, keys.Insert(ctx, newAPIKey(u.ID, u.TenantID, p)))
		time.Sleep(10 * time.Millisecond) // created_at 区分度
	}

	got, err := keys.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// created_at DESC：最后插入的在最前
	assert.Equal(t, "CCCC4444", got[0].KeyPrefix)
	assert.Equal(t, "AAAA2222", got[2].KeyPrefix)
}

func TestAPIKey_ListByUser_Empty(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	got, err := keys.ListByUser(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// === Revoke ===

func TestAPIKey_Revoke(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "REVOKE22")
	require.NoError(t, keys.Insert(ctx, k))

	require.NoError(t, keys.Revoke(ctx, k.ID))

	got, err := keys.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RevokedAt)
	assert.True(t, got.IsRevoked())
}

func TestAPIKey_Revoke_Idempotent(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "REVOK222")
	require.NoError(t, keys.Insert(ctx, k))

	require.NoError(t, keys.Revoke(ctx, k.ID))
	first, _ := keys.GetByID(ctx, k.ID)

	// 再调一遍：应成功（幂等），revoked_at 不变（COALESCE 保留首次值）
	require.NoError(t, keys.Revoke(ctx, k.ID))
	second, _ := keys.GetByID(ctx, k.ID)

	require.NotNil(t, first.RevokedAt)
	require.NotNil(t, second.RevokedAt)
	assert.True(t, first.RevokedAt.Equal(*second.RevokedAt),
		"幂等 Revoke：revoked_at 应保留首次时间")
}

func TestAPIKey_Revoke_NotFound(t *testing.T) {
	_, keys, _ := setupAPIKeyRepo(t)
	err := keys.Revoke(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
}

// === UpdateLastUsed ===

func TestAPIKey_UpdateLastUsed(t *testing.T) {
	_, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	k := newAPIKey(u.ID, u.TenantID, "USEDFLAG")
	require.NoError(t, keys.Insert(ctx, k))

	require.NoError(t, keys.UpdateLastUsed(ctx, k.ID))

	got, err := keys.GetByID(ctx, k.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastUsedAt)
	assert.WithinDuration(t, time.Now(), *got.LastUsedAt, 5*time.Second)
}

func TestAPIKey_UpdateLastUsed_NotFound(t *testing.T) {
	_, keys, _ := setupAPIKeyRepo(t)
	err := keys.UpdateLastUsed(context.Background(),
		"00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
}

// === FK CASCADE：user 删，api_keys 自动删 ===

func TestAPIKey_CascadesOnUserDelete(t *testing.T) {
	users, keys, u := setupAPIKeyRepo(t)
	ctx := context.Background()

	for _, p := range []string{"CASC1234", "CASC4444"} {
		require.NoError(t, keys.Insert(ctx, newAPIKey(u.ID, u.TenantID, p)))
	}

	pool := users.(*pgRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u.ID)
	require.NoError(t, err)

	got, err := keys.ListByUser(ctx, u.ID)
	require.NoError(t, err)
	assert.Empty(t, got, "ON DELETE CASCADE 应级联删除 api_keys")
}
