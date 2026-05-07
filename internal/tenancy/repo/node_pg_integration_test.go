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

func setupNodeRepo(t *testing.T) (AccountRepository, NodeRepository, *domain.Account) {
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
	nodes := NewNodePG(pool)

	a := &domain.Account{Slug: "alpha", DisplayName: "Alpha", Status: domain.AccountActive}
	require.NoError(t, accounts.Insert(ctx, a))
	return accounts, nodes, a
}

func newNode(tenantID, name string) *domain.Node {
	return &domain.Node{
		TenantID: tenantID,
		Name:     name,
		Version:  "1.0.0",
	}
}

// === Insert ===

func TestNode_Insert_Roundtrip(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()

	n := newNode(a.ID, "agent-01")
	n.Capabilities = []string{"scan:web", "scan:port"}
	require.NoError(t, nodes.Insert(ctx, n))
	assert.NotEmpty(t, n.ID)

	got, err := nodes.GetByID(ctx, n.ID)
	require.NoError(t, err)
	assert.Equal(t, "agent-01", got.Name)
	assert.Equal(t, "1.0.0", got.Version)
	assert.Equal(t, domain.NodePending, got.Status)
	assert.ElementsMatch(t, []string{"scan:web", "scan:port"}, got.Capabilities)
}

func TestNode_Insert_NameUniquePerTenant(t *testing.T) {
	accounts, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	require.NoError(t, nodes.Insert(ctx, newNode(a.ID, "agent-01")))
	err := nodes.Insert(ctx, newNode(a.ID, "agent-01"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNameExists, c)

	other := &domain.Account{Slug: "bravo", DisplayName: "Bravo"}
	require.NoError(t, accounts.Insert(ctx, other))
	require.NoError(t, nodes.Insert(ctx, newNode(other.ID, "agent-01")))
}

func TestNode_Insert_NameUnique_CaseInsensitive(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	require.NoError(t, nodes.Insert(ctx, newNode(a.ID, "Agent-01")))
	err := nodes.Insert(ctx, newNode(a.ID, "AGENT-01"))
	require.Error(t, err, "lower(name) UNIQUE 应忽略大小写")
}

func TestNode_Insert_BadDomain(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	n := newNode(a.ID, "")
	err := nodes.Insert(context.Background(), n)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestNode_Insert_TenantFK(t *testing.T) {
	_, nodes, _ := setupNodeRepo(t)
	err := nodes.Insert(context.Background(),
		newNode("00000000-0000-0000-0000-000000000aaa", "agent-01"))
	require.Error(t, err)
}

// === GetByID ===

func TestNode_GetByID_NotFoundOrDeleted(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()

	_, err := nodes.GetByID(ctx, "00000000-0000-0000-0000-000000000111")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNotFound, c)

	n := newNode(a.ID, "soft")
	require.NoError(t, nodes.Insert(ctx, n))
	require.NoError(t, nodes.SoftDelete(ctx, n.ID))
	_, err = nodes.GetByID(ctx, n.ID)
	require.Error(t, err)
}

// === UpdateStatus ===

func TestNode_UpdateStatus(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	n := newNode(a.ID, "lifecycle")
	require.NoError(t, nodes.Insert(ctx, n))

	require.NoError(t, nodes.UpdateStatus(ctx, n.ID, domain.NodeOnline))
	got, err := nodes.GetByID(ctx, n.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.NodeOnline, got.Status)

	require.NoError(t, nodes.UpdateStatus(ctx, n.ID, domain.NodeDisabled))
	got, err = nodes.GetByID(ctx, n.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.NodeDisabled, got.Status)
}

func TestNode_UpdateStatus_BadStatus(t *testing.T) {
	_, nodes, _ := setupNodeRepo(t)
	err := nodes.UpdateStatus(context.Background(),
		"00000000-0000-0000-0000-000000000aaa", domain.NodeStatus("bogus"))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestNode_UpdateStatus_NotFound(t *testing.T) {
	_, nodes, _ := setupNodeRepo(t)
	err := nodes.UpdateStatus(context.Background(),
		"00000000-0000-0000-0000-000000000aaa", domain.NodeOnline)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNotFound, c)
}

// === SoftDelete ===

func TestNode_SoftDelete_AllowsNameReuse(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	n := newNode(a.ID, "reuse")
	require.NoError(t, nodes.Insert(ctx, n))
	require.NoError(t, nodes.SoftDelete(ctx, n.ID))

	n2 := newNode(a.ID, "reuse")
	require.NoError(t, nodes.Insert(ctx, n2))
	assert.NotEqual(t, n.ID, n2.ID)
}

// === List ===

func TestNode_List_FilterByTenantAndStatus(t *testing.T) {
	accounts, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		require.NoError(t, nodes.Insert(ctx, newNode(a.ID, name)))
	}
	got, _, err := nodes.List(ctx, NodeFilter{TenantID: a.ID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.NoError(t, nodes.UpdateStatus(ctx, got[0].ID, domain.NodeOnline))

	other := &domain.Account{Slug: "other", DisplayName: "Other"}
	require.NoError(t, accounts.Insert(ctx, other))
	require.NoError(t, nodes.Insert(ctx, newNode(other.ID, "other-1")))

	rs, total, err := nodes.List(ctx,
		NodeFilter{TenantID: a.ID, Status: domain.NodePending}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, rs, 2)
}

func TestNode_List_KeywordILIKE(t *testing.T) {
	_, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	for _, name := range []string{"agent-web-1", "agent-port-1", "scanner-2"} {
		require.NoError(t, nodes.Insert(ctx, newNode(a.ID, name)))
	}
	rs, total, err := nodes.List(ctx,
		NodeFilter{TenantID: a.ID, Keyword: "agent"}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, rs, 2)
}

// === Cascade ===

func TestNode_AccountCascadeDelete(t *testing.T) {
	accounts, nodes, a := setupNodeRepo(t)
	ctx := context.Background()
	require.NoError(t, nodes.Insert(ctx, newNode(a.ID, "n1")))
	require.NoError(t, nodes.Insert(ctx, newNode(a.ID, "n2")))

	pool := accounts.(*pgAccountRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1::uuid`, a.ID)
	require.NoError(t, err)

	rs, total, err := nodes.List(ctx, NodeFilter{TenantID: a.ID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, rs)
}
