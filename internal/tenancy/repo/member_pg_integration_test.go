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

// setupMemberRepo 装好 account + project + user fixture + 三个 repo。
//
// user 用 raw SQL 插（避开 identity 包；FK 满足即可）。
func setupMemberRepo(t *testing.T) (
	*domain.Account,
	*domain.Project,
	string, // user1 id
	string, // user2 id
	ProjectMemberRepository,
	*pgxpool.Pool,
) {
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
	projects := NewProjectPG(pool)
	members := NewProjectMemberPG(pool)

	a := &domain.Account{
		Slug: "alpha", DisplayName: "Alpha", Status: domain.AccountActive,
	}
	require.NoError(t, accounts.Insert(ctx, a))

	p := &domain.Project{TenantID: a.ID, Name: "demo"}
	require.NoError(t, projects.Insert(ctx, p))

	user1 := insertTestUser(t, pool, "alice", a.ID)
	user2 := insertTestUser(t, pool, "bob", a.ID)

	return a, p, user1, user2, members, pool
}

// insertTestUser 直接 SQL 插一行 ProjectAdmin，绕开 identity domain（FK 用）。
func insertTestUser(t *testing.T, pool *pgxpool.Pool, username, tenantID string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		INSERT INTO users (
			tenant_id, username, password_hash, email, role, status,
			token_version, must_change_password
		) VALUES (
			$1::uuid, $2, 'argon2id$irrelevant', $3, 'PROJECT_ADMIN', 'active', 0, false
		)
		RETURNING id::text
	`, tenantID, username, username+"@example.com").Scan(&id)
	require.NoError(t, err)
	return id
}

// === Add ===

func TestMember_Add_Roundtrip(t *testing.T) {
	a, p, user1, _, members, _ := setupMemberRepo(t)
	ctx := context.Background()

	m := &domain.ProjectMember{
		ProjectID: p.ID,
		UserID:    user1,
		TenantID:  a.ID,
	}
	require.NoError(t, members.Add(ctx, m))
	assert.False(t, m.AddedAt.IsZero(), "Add 应填 added_at")

	exists, err := members.Exists(ctx, p.ID, user1)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestMember_Add_Duplicate(t *testing.T) {
	a, p, user1, _, members, _ := setupMemberRepo(t)
	ctx := context.Background()

	m := &domain.ProjectMember{ProjectID: p.ID, UserID: user1, TenantID: a.ID}
	require.NoError(t, members.Add(ctx, m))

	err := members.Add(ctx, &domain.ProjectMember{
		ProjectID: p.ID, UserID: user1, TenantID: a.ID,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectMemberExists, c)
}

func TestMember_Add_BadDomain(t *testing.T) {
	_, p, user1, _, members, _ := setupMemberRepo(t)
	ctx := context.Background()

	err := members.Add(ctx, &domain.ProjectMember{ProjectID: p.ID, UserID: user1})
	require.Error(t, err, "缺 tenant_id 应被域内拦下")
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === Remove ===

func TestMember_Remove(t *testing.T) {
	a, p, user1, _, members, _ := setupMemberRepo(t)
	ctx := context.Background()
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p.ID, UserID: user1, TenantID: a.ID}))

	require.NoError(t, members.Remove(ctx, p.ID, user1))

	exists, err := members.Exists(ctx, p.ID, user1)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestMember_Remove_NotFound(t *testing.T) {
	_, p, user1, _, members, _ := setupMemberRepo(t)
	err := members.Remove(context.Background(), p.ID, user1)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectMemberNotFound, c)
}

// === ListByProject ===

func TestMember_ListByProject(t *testing.T) {
	a, p, user1, user2, members, _ := setupMemberRepo(t)
	ctx := context.Background()
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p.ID, UserID: user1, TenantID: a.ID}))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p.ID, UserID: user2, TenantID: a.ID}))

	got, err := members.ListByProject(ctx, p.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, user1, got[0].UserID, "added_at ASC：先 user1")
	assert.Equal(t, user2, got[1].UserID)
}

// === ListProjectIDsByUser ===

func TestMember_ListProjectIDsByUser(t *testing.T) {
	a, p1, user1, _, members, pool := setupMemberRepo(t)
	ctx := context.Background()

	// 多创建 1 个项目并加 user1 进去
	projects := NewProjectPG(pool)
	p2 := &domain.Project{TenantID: a.ID, Name: "second"}
	require.NoError(t, projects.Insert(ctx, p2))

	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p1.ID, UserID: user1, TenantID: a.ID}))
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p2.ID, UserID: user1, TenantID: a.ID}))

	ids, err := members.ListProjectIDsByUser(ctx, user1)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{p1.ID, p2.ID}, ids)
}

// === Cascade：项目删 / 用户删 → member 自动删 ===

func TestMember_CascadeOnProjectDelete(t *testing.T) {
	a, p, user1, _, members, pool := setupMemberRepo(t)
	ctx := context.Background()
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p.ID, UserID: user1, TenantID: a.ID}))

	// 硬删项目（绕过 SoftDelete）
	_, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1::uuid`, p.ID)
	require.NoError(t, err)

	exists, err := members.Exists(ctx, p.ID, user1)
	require.NoError(t, err)
	assert.False(t, exists, "ON DELETE CASCADE")
}

func TestMember_CascadeOnUserDelete(t *testing.T) {
	a, p, user1, _, members, pool := setupMemberRepo(t)
	ctx := context.Background()
	require.NoError(t, members.Add(ctx,
		&domain.ProjectMember{ProjectID: p.ID, UserID: user1, TenantID: a.ID}))

	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, user1)
	require.NoError(t, err)

	exists, err := members.Exists(ctx, p.ID, user1)
	require.NoError(t, err)
	assert.False(t, exists, "ON DELETE CASCADE")
}
