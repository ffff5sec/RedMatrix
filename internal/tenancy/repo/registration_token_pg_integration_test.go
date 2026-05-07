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
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

func setupTokenRepo(t *testing.T) (RegistrationTokenRepository, *domain.Account) {
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

	accounts := NewAccountPG(pool)
	tokens := NewRegistrationTokenPG(pool)

	a := &domain.Account{Slug: "alpha", DisplayName: "Alpha", Status: domain.AccountActive}
	require.NoError(t, accounts.Insert(ctx, a))
	return tokens, a
}

func newToken(tenantID, name, hash string) *domain.RegistrationToken {
	return &domain.RegistrationToken{
		TenantID:  tenantID,
		Name:      name,
		TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func makeHash(s string) string {
	// 测试用伪 hash —— 任意 64 字符 hex 都能通过 schema CHECK
	return strings.Repeat(s, 64/len(s))[:64]
}

// === Insert ===

func TestRegToken_Insert_Roundtrip(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()

	tok := newToken(a.ID, "batch-1", makeHash("a"))
	require.NoError(t, tokens.Insert(ctx, tok))
	assert.NotEmpty(t, tok.ID)

	got, err := tokens.GetByHash(ctx, tok.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
	assert.Equal(t, "batch-1", got.Name)
	assert.Nil(t, got.UsedAt)
	assert.Nil(t, got.RevokedAt)
}

func TestRegToken_Insert_HashUnique(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()

	require.NoError(t, tokens.Insert(ctx, newToken(a.ID, "t1", makeHash("a"))))
	err := tokens.Insert(ctx, newToken(a.ID, "t2", makeHash("a")))
	require.Error(t, err, "同 hash 应冲突")
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRegToken_Insert_BadHashFormat(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	tok := newToken(a.ID, "bad", "deadbeef") // 非 64 字符
	err := tokens.Insert(context.Background(), tok)
	require.Error(t, err)
	// 域内拦下，返 ErrInvalidInput
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestRegToken_Insert_FK(t *testing.T) {
	tokens, _ := setupTokenRepo(t)
	tok := newToken("00000000-0000-0000-0000-00000000aaaa", "x", makeHash("b"))
	err := tokens.Insert(context.Background(), tok)
	require.Error(t, err, "tenant 不存在 → FK 违反")
}

// === GetByHash / GetByID ===

func TestRegToken_GetByHash_NotFound(t *testing.T) {
	tokens, _ := setupTokenRepo(t)
	_, err := tokens.GetByHash(context.Background(), makeHash("z"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRegToken_GetByID(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()
	tok := newToken(a.ID, "x", makeHash("c"))
	require.NoError(t, tokens.Insert(ctx, tok))

	got, err := tokens.GetByID(ctx, tok.ID)
	require.NoError(t, err)
	assert.Equal(t, tok.TokenHash, got.TokenHash)

	_, err = tokens.GetByID(ctx, "00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
}

// === Revoke ===

func TestRegToken_Revoke_Idempotent(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()
	tok := newToken(a.ID, "rev", makeHash("d"))
	require.NoError(t, tokens.Insert(ctx, tok))

	require.NoError(t, tokens.Revoke(ctx, tok.ID))
	first, _ := tokens.GetByID(ctx, tok.ID)
	require.NotNil(t, first.RevokedAt)

	// 再 Revoke 一次仍成功；revoked_at 保留首次（COALESCE）
	require.NoError(t, tokens.Revoke(ctx, tok.ID))
	second, _ := tokens.GetByID(ctx, tok.ID)
	assert.True(t, first.RevokedAt.Equal(*second.RevokedAt))
}

func TestRegToken_Revoke_NotFound(t *testing.T) {
	tokens, _ := setupTokenRepo(t)
	err := tokens.Revoke(context.Background(),
		"00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
}

// === MarkUsed 单次性 ===

func TestRegToken_MarkUsed_SingleUse(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()
	tok := newToken(a.ID, "used", makeHash("e"))
	require.NoError(t, tokens.Insert(ctx, tok))

	require.NoError(t, tokens.MarkUsed(ctx, tok.ID))

	// 第二次 → invalid（双花防护）
	err := tokens.MarkUsed(ctx, tok.ID)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRegToken_MarkUsed_OnRevokedFails(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()
	tok := newToken(a.ID, "rev-then-use", makeHash("f"))
	require.NoError(t, tokens.Insert(ctx, tok))
	require.NoError(t, tokens.Revoke(ctx, tok.ID))

	err := tokens.MarkUsed(ctx, tok.ID)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

// === ListByTenant ===

func TestRegToken_ListByTenant(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()

	for i, n := range []string{"first", "second", "third"} {
		tok := newToken(a.ID, n, makeHash(string(rune('a'+i))))
		require.NoError(t, tokens.Insert(ctx, tok))
		time.Sleep(10 * time.Millisecond)
	}

	got, err := tokens.ListByTenant(ctx, a.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "third", got[0].Name, "created_at DESC")
	assert.Equal(t, "first", got[2].Name)
}

// === Cascade ===

func TestRegToken_AccountCascade(t *testing.T) {
	tokens, a := setupTokenRepo(t)
	ctx := context.Background()
	require.NoError(t, tokens.Insert(ctx, newToken(a.ID, "x", makeHash("g"))))
	require.NoError(t, tokens.Insert(ctx, newToken(a.ID, "y", makeHash("h"))))

	pool := tokens.(*pgRegistrationTokenRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1::uuid`, a.ID)
	require.NoError(t, err)

	got, err := tokens.ListByTenant(ctx, a.ID)
	require.NoError(t, err)
	assert.Empty(t, got, "ON DELETE CASCADE")
}
