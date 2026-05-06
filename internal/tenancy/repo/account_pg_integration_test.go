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
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

func setupAccountRepo(t *testing.T) AccountRepository {
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

	return NewAccountPG(pool)
}

func newAccount(slug string) *domain.Account {
	return &domain.Account{
		Slug:        slug,
		DisplayName: "Test " + slug,
		Status:      domain.AccountActive,
	}
}

// === Insert ===

func TestAccount_Insert_Roundtrip_GeneratedUUID(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	a := newAccount("alpha")
	require.NoError(t, r.Insert(ctx, a))
	assert.NotEmpty(t, a.ID, "Insert 应回填 id")

	got, err := r.GetByID(ctx, a.ID)
	require.NoError(t, err)
	assert.Equal(t, a.ID, got.ID)
	assert.Equal(t, "alpha", got.Slug)
	assert.Equal(t, "Test alpha", got.DisplayName)
	assert.Equal(t, "standard", got.Plan)
	assert.Equal(t, domain.AccountActive, got.Status)
	assert.NotNil(t, got.Settings)
	assert.Empty(t, got.Settings, "默认 settings 是空对象")
}

func TestAccount_Insert_FixedUUID(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	const fixed = "00000000-0000-0000-0000-000000000001"
	a := newAccount("default")
	a.ID = fixed
	require.NoError(t, r.Insert(ctx, a))
	assert.Equal(t, fixed, a.ID)

	got, err := r.GetByID(ctx, fixed)
	require.NoError(t, err)
	assert.Equal(t, "default", got.Slug)
}

func TestAccount_Insert_SlugUniqueViolation(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	require.NoError(t, r.Insert(ctx, newAccount("alpha")))
	err := r.Insert(ctx, newAccount("alpha"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAccountSlugExists, c)
}

func TestAccount_Insert_BadDomain(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	a := newAccount("alpha")
	a.Slug = "Bad-Case"
	err := r.Insert(ctx, a)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === GetByID / GetBySlug ===

func TestAccount_GetByID_NotFound(t *testing.T) {
	r := setupAccountRepo(t)
	_, err := r.GetByID(context.Background(),
		"00000000-0000-0000-0000-00000000000a")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAccountNotFound, c)
}

func TestAccount_GetBySlug(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	require.NoError(t, r.Insert(ctx, newAccount("alpha")))
	got, err := r.GetBySlug(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, "alpha", got.Slug)

	_, err = r.GetBySlug(ctx, "missing")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAccountNotFound, c)
}

// === ListActive ===

func TestAccount_ListActive_OrderByCreatedAsc(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	for _, slug := range []string{"alpha", "bravo", "charlie"} {
		require.NoError(t, r.Insert(ctx, newAccount(slug)))
		time.Sleep(10 * time.Millisecond)
	}

	got, err := r.ListActive(ctx)
	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "alpha", got[0].Slug, "created_at ASC")
	assert.Equal(t, "charlie", got[2].Slug)
}

func TestAccount_ListActive_ExcludesSoftDeleted(t *testing.T) {
	r := setupAccountRepo(t)
	ctx := context.Background()

	require.NoError(t, r.Insert(ctx, newAccount("alpha")))
	require.NoError(t, r.Insert(ctx, newAccount("bravo")))

	// 直接 SQL 软删 alpha
	pool := r.(*pgAccountRepo).pool
	_, err := pool.Exec(ctx, `UPDATE accounts SET deleted_at = now() WHERE slug = $1`, "alpha")
	require.NoError(t, err)

	got, err := r.ListActive(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "bravo", got[0].Slug)
}
