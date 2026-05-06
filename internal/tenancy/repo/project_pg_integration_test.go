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

func setupProjectRepo(t *testing.T) (AccountRepository, ProjectRepository, *domain.Account) {
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

	a := &domain.Account{
		Slug:        "alpha",
		DisplayName: "Alpha",
		Status:      domain.AccountActive,
	}
	require.NoError(t, accounts.Insert(ctx, a))
	return accounts, projects, a
}

func newProject(tenantID, name string) *domain.Project {
	return &domain.Project{
		TenantID: tenantID,
		Name:     name,
	}
}

// === Insert ===

func TestProject_Insert_Roundtrip(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()

	p := newProject(a.ID, "demo")
	p.Description = "demo project"
	p.Settings = map[string]any{"alert_threshold": 0.8}
	require.NoError(t, projects.Insert(ctx, p))
	assert.NotEmpty(t, p.ID)

	got, err := projects.GetByID(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, "demo", got.Name)
	assert.Equal(t, "demo project", got.Description)
	assert.Equal(t, domain.ProjectActive, got.Status)
	assert.Equal(t, 0.8, got.Settings["alert_threshold"])
}

func TestProject_Insert_NameUniquePerTenant(t *testing.T) {
	accounts, projects, a := setupProjectRepo(t)
	ctx := context.Background()

	require.NoError(t, projects.Insert(ctx, newProject(a.ID, "demo")))
	err := projects.Insert(ctx, newProject(a.ID, "demo"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNameExists, c)

	// 同名在不同 tenant 下应允许
	other := &domain.Account{Slug: "bravo", DisplayName: "Bravo"}
	require.NoError(t, accounts.Insert(ctx, other))
	require.NoError(t, projects.Insert(ctx, newProject(other.ID, "demo")))
}

func TestProject_Insert_NameUnique_CaseInsensitive(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()

	require.NoError(t, projects.Insert(ctx, newProject(a.ID, "Demo")))
	err := projects.Insert(ctx, newProject(a.ID, "DEMO"))
	require.Error(t, err, "lower(name) UNIQUE 应忽略大小写")
}

func TestProject_Insert_TenantFK(t *testing.T) {
	_, projects, _ := setupProjectRepo(t)
	err := projects.Insert(context.Background(),
		newProject("00000000-0000-0000-0000-000000000aaa", "demo"))
	require.Error(t, err, "tenant 不存在 → FK 违反")
}

// === GetByID ===

func TestProject_GetByID_NotFoundOrDeleted(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()

	_, err := projects.GetByID(ctx, "00000000-0000-0000-0000-000000000111")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)

	// 软删后 GetByID 也应返 NotFound
	p := newProject(a.ID, "soft")
	require.NoError(t, projects.Insert(ctx, p))
	require.NoError(t, projects.SoftDelete(ctx, p.ID))
	_, err = projects.GetByID(ctx, p.ID)
	require.Error(t, err)
	c, _ = errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

// === Archive / Unarchive ===

func TestProject_ArchiveUnarchive(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	p := newProject(a.ID, "lifecycle")
	require.NoError(t, projects.Insert(ctx, p))

	require.NoError(t, projects.Archive(ctx, p.ID))
	got, err := projects.GetByID(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ProjectArchived, got.Status)
	require.NotNil(t, got.ArchivedAt)

	require.NoError(t, projects.Unarchive(ctx, p.ID))
	got, err = projects.GetByID(ctx, p.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ProjectActive, got.Status)
	assert.Nil(t, got.ArchivedAt)
}

func TestProject_Archive_Idempotent(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	p := newProject(a.ID, "twice-archive")
	require.NoError(t, projects.Insert(ctx, p))

	require.NoError(t, projects.Archive(ctx, p.ID))
	first, _ := projects.GetByID(ctx, p.ID)
	require.NotNil(t, first.ArchivedAt)

	require.NoError(t, projects.Archive(ctx, p.ID))
	second, _ := projects.GetByID(ctx, p.ID)
	require.NotNil(t, second.ArchivedAt)
	assert.True(t, first.ArchivedAt.Equal(*second.ArchivedAt),
		"幂等：archived_at 保留首次时间（COALESCE）")
}

func TestProject_Archive_NotFound(t *testing.T) {
	_, projects, _ := setupProjectRepo(t)
	err := projects.Archive(context.Background(),
		"00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

// === SoftDelete ===

func TestProject_SoftDelete(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	p := newProject(a.ID, "to-delete")
	require.NoError(t, projects.Insert(ctx, p))

	require.NoError(t, projects.SoftDelete(ctx, p.ID))

	// GetByID 已不可见
	_, err := projects.GetByID(ctx, p.ID)
	require.Error(t, err)
}

func TestProject_SoftDelete_AllowsNameReuse(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	p := newProject(a.ID, "reuse")
	require.NoError(t, projects.Insert(ctx, p))
	require.NoError(t, projects.SoftDelete(ctx, p.ID))

	// 同名应可以重新创建（partial unique index）
	p2 := newProject(a.ID, "reuse")
	require.NoError(t, projects.Insert(ctx, p2))
	assert.NotEqual(t, p.ID, p2.ID)
}

// === List ===

func TestProject_List_FilterByTenantAndStatus(t *testing.T) {
	accounts, projects, a := setupProjectRepo(t)
	ctx := context.Background()

	// 在 a 下放 3 项目（2 active，1 archived）
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		require.NoError(t, projects.Insert(ctx, newProject(a.ID, n)))
	}
	got, _, err := projects.List(ctx, ProjectFilter{TenantID: a.ID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.NoError(t, projects.Archive(ctx, got[0].ID))

	// 另一个 tenant 一个项目
	other := &domain.Account{Slug: "other", DisplayName: "Other"}
	require.NoError(t, accounts.Insert(ctx, other))
	require.NoError(t, projects.Insert(ctx, newProject(other.ID, "x")))

	// 仅 a 下 active：2 个
	rs, total, err := projects.List(ctx,
		ProjectFilter{TenantID: a.ID, Status: domain.ProjectActive}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, rs, 2)
	for _, p := range rs {
		assert.Equal(t, a.ID, p.TenantID)
		assert.Equal(t, domain.ProjectActive, p.Status)
	}
}

func TestProject_List_KeywordILIKE(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	for _, n := range []string{"web-scan", "api-scan", "internal-scan", "weekly-report"} {
		require.NoError(t, projects.Insert(ctx, newProject(a.ID, n)))
	}
	rs, total, err := projects.List(ctx,
		ProjectFilter{TenantID: a.ID, Keyword: "scan"}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, rs, 3)
}

func TestProject_List_Pagination(t *testing.T) {
	_, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		require.NoError(t, projects.Insert(ctx,
			newProject(a.ID, "p-"+string(rune('a'+i)))))
	}
	page1, total, err := projects.List(ctx,
		ProjectFilter{TenantID: a.ID}, Page{Page: 1, PageSize: 3})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, page1, 3)

	page3, _, err := projects.List(ctx,
		ProjectFilter{TenantID: a.ID}, Page{Page: 3, PageSize: 3})
	require.NoError(t, err)
	require.Len(t, page3, 1, "7 行 / 3 大小 → 第 3 页 1 条")
}

// === Cascade：account 硬删 → projects 跟着删 ===

func TestProject_AccountCascadeDelete(t *testing.T) {
	accounts, projects, a := setupProjectRepo(t)
	ctx := context.Background()
	require.NoError(t, projects.Insert(ctx, newProject(a.ID, "p1")))
	require.NoError(t, projects.Insert(ctx, newProject(a.ID, "p2")))

	pool := accounts.(*pgAccountRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1::uuid`, a.ID)
	require.NoError(t, err)

	// 项目应已 cascade 删（GetByID 都返 NotFound — 不仅是软删）
	rs, total, err := projects.List(ctx, ProjectFilter{TenantID: a.ID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, rs)
}
