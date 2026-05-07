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

	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

func setupAllowedNodesRepo(t *testing.T) (
	AllowedNodesRepository,
	*domain.Account,
	*domain.Project,
	[]string, // node ids: at least 3
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
	nodes := NewNodePG(pool)
	allowed := NewAllowedNodesPG(pool)

	a := &domain.Account{Slug: "alpha", DisplayName: "Alpha", Status: domain.AccountActive}
	require.NoError(t, accounts.Insert(ctx, a))

	p := &domain.Project{TenantID: a.ID, Name: "demo"}
	require.NoError(t, projects.Insert(ctx, p))

	var nodeIDs []string
	for _, name := range []string{"n1", "n2", "n3"} {
		n := &domain.Node{TenantID: a.ID, Name: name, Version: "1.0.0"}
		require.NoError(t, nodes.Insert(ctx, n))
		nodeIDs = append(nodeIDs, n.ID)
	}
	return allowed, a, p, nodeIDs
}

// === Get default = AllNodes ===

func TestAllowed_Get_DefaultAllNodes(t *testing.T) {
	allowed, _, p, _ := setupAllowedNodesRepo(t)
	got, err := allowed.Get(context.Background(), p.ID)
	require.NoError(t, err)
	assert.True(t, got.AllNodes, "无任何行 → AllNodes=true")
	assert.Empty(t, got.NodeIDs)
}

// === Set + Get ===

func TestAllowed_SetAndGet(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()

	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0], ids[1]}, ""))

	got, err := allowed.Get(ctx, p.ID)
	require.NoError(t, err)
	assert.False(t, got.AllNodes)
	assert.ElementsMatch(t, []string{ids[0], ids[1]}, got.NodeIDs)
}

// === Set 全量替换 ===

func TestAllowed_Set_OverwritePrevious(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()

	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0], ids[1]}, ""))
	// 覆盖：仅留 ids[2]
	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[2]}, ""))

	got, err := allowed.Get(ctx, p.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{ids[2]}, got.NodeIDs)
}

// === ClearAll 恢复 ALL ===

func TestAllowed_ClearAll(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()

	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0]}, ""))
	require.NoError(t, allowed.ClearAll(ctx, p.ID))

	got, err := allowed.Get(ctx, p.ID)
	require.NoError(t, err)
	assert.True(t, got.AllNodes, "ClearAll 后回到 ALL 默认")
}

// === IsAllowed 各路径 ===

func TestAllowed_IsAllowed_AllNodesDefault(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ok, err := allowed.IsAllowed(context.Background(), p.ID, ids[0])
	require.NoError(t, err)
	assert.True(t, ok, "无白名单 → 任何节点都允许")
}

func TestAllowed_IsAllowed_Whitelist(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()
	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0]}, ""))

	ok, err := allowed.IsAllowed(ctx, p.ID, ids[0])
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = allowed.IsAllowed(ctx, p.ID, ids[1])
	require.NoError(t, err)
	assert.False(t, ok, "白名单外不允许")
}

// === Cascade：删 project / node 自动清条目 ===

func TestAllowed_CascadeOnProjectDelete(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()
	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0], ids[1]}, ""))

	pool := allowed.(*pgAllowedNodesRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1::uuid`, p.ID)
	require.NoError(t, err)

	got, err := allowed.Get(ctx, p.ID)
	require.NoError(t, err)
	assert.True(t, got.AllNodes, "项目硬删 → 白名单 cascade 清空")
}

func TestAllowed_CascadeOnNodeDelete(t *testing.T) {
	allowed, _, p, ids := setupAllowedNodesRepo(t)
	ctx := context.Background()
	require.NoError(t, allowed.Set(ctx, p.ID, []string{ids[0], ids[1]}, ""))

	pool := allowed.(*pgAllowedNodesRepo).pool
	_, err := pool.Exec(ctx, `DELETE FROM nodes WHERE id = $1::uuid`, ids[0])
	require.NoError(t, err)

	got, err := allowed.Get(ctx, p.ID)
	require.NoError(t, err)
	assert.False(t, got.AllNodes, "node 删 → 仅清该 node 行；其他保留")
	assert.ElementsMatch(t, []string{ids[1]}, got.NodeIDs)
}
