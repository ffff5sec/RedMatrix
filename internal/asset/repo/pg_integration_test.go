//go:build integration

// pg_integration_test.go: asset pgRepo 真 PG 集成测试（PR-S18-C）。
//
// 覆盖范围（pg.go）：
//   - UpsertBulk 新行：result_count 初始等于传入 delta
//   - 同 (tenant, project, kind, value) 重复 UPSERT：result_count 累加 +
//     last_seen 滚动更新，first_seen 不变
//   - PR-S18-B：长 URL（接近 VARCHAR(2048) 上限）UPSERT 不爆 btree
//     单行 size 上限 —— 验证 idx_assets_unique_hash + value_sha256 hash 索引
//   - List 按 kind / project / keyword 过滤 + 分页 + ProjectIDs ANY 路径
//   - GetByID NotFound
//
// 设计：testcontainers 起 PG → migrate.Up → pgxpool；每个 setup 起一个独立
// 容器（与 scan/repo 同模式）；container 在 t.Cleanup 内 Terminate。
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

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

type assetFixture struct {
	pool       *pgxpool.Pool
	tenantID   string
	projectID  string
	projectID2 string // 第二个 project，用于 ProjectIDs / 隔离测试
	tenantID2  string // 第二个 tenant，用于跨 tenant 隔离
	repo       Repository
}

// setupAssetRepo 起容器 + 跑迁移 + 插 2 个 account + 2 个 project。
func setupAssetRepo(t *testing.T) assetFixture {
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

	var t1, t2, p1, p2 string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO accounts (slug, display_name) VALUES ('alpha', 'Alpha') RETURNING id::text`).Scan(&t1))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO accounts (slug, display_name) VALUES ('bravo', 'Bravo') RETURNING id::text`).Scan(&t2))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, name) VALUES ($1::uuid, 'demo') RETURNING id::text`, t1).Scan(&p1))
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, name) VALUES ($1::uuid, 'demo2') RETURNING id::text`, t1).Scan(&p2))

	return assetFixture{
		pool: pool, tenantID: t1, tenantID2: t2,
		projectID: p1, projectID2: p2,
		repo: NewPG(pool),
	}
}

func newAsset(fix assetFixture, kind domain.Kind, value string, delta int) *domain.Asset {
	return &domain.Asset{
		TenantID:    fix.tenantID,
		ProjectID:   fix.projectID,
		Kind:        kind,
		Value:       value,
		ResultCount: delta,
	}
}

// === UpsertBulk ===

func TestAsset_UpsertBulk_NewRows(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	rows := []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.0.1", 3),
		newAsset(fix, domain.KindURL, "https://example.com/", 1),
	}
	require.NoError(t, fix.repo.UpsertBulk(ctx, rows))

	got, total, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	require.Equal(t, 2, total)

	byVal := map[string]*domain.Asset{}
	for _, a := range got {
		byVal[a.Value] = a
	}
	require.Contains(t, byVal, "10.0.0.1")
	require.Contains(t, byVal, "https://example.com/")
	assert.Equal(t, 3, byVal["10.0.0.1"].ResultCount, "新行 result_count = 传入 delta")
	assert.Equal(t, 1, byVal["https://example.com/"].ResultCount)
	assert.False(t, byVal["10.0.0.1"].FirstSeen.IsZero())
	assert.False(t, byVal["10.0.0.1"].LastSeen.IsZero())
}

func TestAsset_UpsertBulk_DeltaDefaultOneWhenZeroOrNeg(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// delta=0 应被实现强制为 1（避免净 0 写）
	rows := []*domain.Asset{newAsset(fix, domain.KindHost, "10.0.0.2", 0)}
	require.NoError(t, fix.repo.UpsertBulk(ctx, rows))

	got, _, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, 1, got[0].ResultCount, "delta=0 → 实现兜底为 1")
}

func TestAsset_UpsertBulk_ConflictAccumulatesAndUpdatesLastSeen(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// 第一次：插入 2 行 host=10.0.0.1 共 delta=5
	require.NoError(t, fix.repo.UpsertBulk(ctx,
		[]*domain.Asset{newAsset(fix, domain.KindHost, "10.0.0.1", 5)}))

	got, _, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 1)
	firstSeen := got[0].FirstSeen
	firstLastSeen := got[0].LastSeen
	id1 := got[0].ID
	assert.Equal(t, 5, got[0].ResultCount)

	// 让时间往前一点（让 last_seen 滚动可测）
	time.Sleep(50 * time.Millisecond)

	// 第二次：同 (tenant, project, kind, value)，delta=3
	require.NoError(t, fix.repo.UpsertBulk(ctx,
		[]*domain.Asset{newAsset(fix, domain.KindHost, "10.0.0.1", 3)}))

	got, _, err = fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 1, "UPSERT 应聚合，不产生第二行")
	assert.Equal(t, id1, got[0].ID, "id 保持")
	assert.Equal(t, 8, got[0].ResultCount, "result_count += delta（5+3=8）")
	assert.True(t, got[0].FirstSeen.Equal(firstSeen), "first_seen 不变")
	assert.True(t, got[0].LastSeen.After(firstLastSeen), "last_seen 滚动前进")
}

func TestAsset_UpsertBulk_DifferentKindNotDeduped(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "example.com", 1),
		newAsset(fix, domain.KindSubdomain, "example.com", 1),
	}))

	got, total, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "host vs subdomain 同 value 不同 kind 不去重")
	assert.Len(t, got, 2)
}

func TestAsset_UpsertBulk_DifferentProjectNotDeduped(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// project1
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.0.5", 1),
	}))
	// project2 同 value
	a2 := newAsset(fix, domain.KindHost, "10.0.0.5", 1)
	a2.ProjectID = fix.projectID2
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{a2}))

	got, total, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "跨 project 不去重")
	assert.Len(t, got, 2)
}

func TestAsset_UpsertBulk_BadDomain(t *testing.T) {
	fix := setupAssetRepo(t)

	// value 空 → ValidateForCreate 应拒
	err := fix.repo.UpsertBulk(context.Background(), []*domain.Asset{
		{TenantID: fix.tenantID, ProjectID: fix.projectID, Kind: domain.KindHost, Value: ""},
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestAsset_UpsertBulk_Empty(t *testing.T) {
	fix := setupAssetRepo(t)
	require.NoError(t, fix.repo.UpsertBulk(context.Background(), nil))
	require.NoError(t, fix.repo.UpsertBulk(context.Background(), []*domain.Asset{}))
}

// === PR-S18-B: 长 URL（hash 索引）===
//
// 原 btree UNIQUE 索引行 = 3 个 UUID + value 全文，value=2000 字符时
// 行 size 超 ~2700 字节硬上限 → INSERT 直接 ERROR "index row size exceeds maximum"。
// PR-S18-B 改 UNIQUE(tenant, project, kind, value_sha256)，行 size 恒 <100B。
//
// 本 case 故意 UPSERT 一个 2000 字符 URL —— 必须无报错；二次 UPSERT 仍命中
// 冲突走 result_count 累加。

func TestAsset_UpsertBulk_LongURLHashIndex(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	longURL := "https://example.com/" + strings.Repeat("a", 1980) // 2000+ chars 限内
	// domain 校验上限是 2048
	if len(longURL) > 2048 {
		longURL = longURL[:2048]
	}

	// 首次插入应成功（不爆 btree size 限制）
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindURL, longURL, 1),
	}))

	got, total, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID, Kind: domain.KindURL}, Page{})
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Len(t, got, 1)
	id1 := got[0].ID
	assert.Equal(t, longURL, got[0].Value, "value 全文保留")

	// 二次 UPSERT 同 URL → 命中 hash 索引冲突 → result_count 累加
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindURL, longURL, 2),
	}))

	got, _, err = fix.repo.List(ctx, Filter{TenantID: fix.tenantID, Kind: domain.KindURL}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 1, "应聚合，不产生第二行")
	assert.Equal(t, id1, got[0].ID)
	assert.Equal(t, 3, got[0].ResultCount, "1 + 2 = 3")
}

// === List 过滤 ===

func TestAsset_List_FilterByKind(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.0.1", 1),
		newAsset(fix, domain.KindHost, "10.0.0.2", 1),
		newAsset(fix, domain.KindURL, "https://a.com/", 1),
		newAsset(fix, domain.KindSubdomain, "api.a.com", 1),
	}))

	got, total, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID, Kind: domain.KindHost},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, got, 2)
	for _, a := range got {
		assert.Equal(t, domain.KindHost, a.Kind)
	}
}

func TestAsset_List_FilterByProject(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// project1: 2 行
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.1.1", 1),
		newAsset(fix, domain.KindHost, "10.0.1.2", 1),
	}))
	// project2: 1 行
	a := newAsset(fix, domain.KindHost, "10.0.2.1", 1)
	a.ProjectID = fix.projectID2
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{a}))

	got, total, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID, ProjectID: fix.projectID},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, got, 2)
}

func TestAsset_List_FilterByProjectIDsANY(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// project1: 2 行
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.3.1", 1),
		newAsset(fix, domain.KindHost, "10.0.3.2", 1),
	}))
	// project2: 1 行
	a := newAsset(fix, domain.KindHost, "10.0.3.5", 1)
	a.ProjectID = fix.projectID2
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{a}))

	// 仅传 projectID（不是 ProjectIDs）→ 走单 project FK 路径
	got, total, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID, ProjectIDs: []string{fix.projectID, fix.projectID2}},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 3, total, "ProjectIDs ANY 应匹配全部")
	require.Len(t, got, 3)

	// 空切片 → caller 短路（实现返空）
	got, total, err = fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID, ProjectIDs: []string{}},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, got)
}

func TestAsset_List_KeywordILIKE(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindURL, "https://web-scan.com/a", 1),
		newAsset(fix, domain.KindURL, "https://api-scan.com/b", 1),
		newAsset(fix, domain.KindHost, "10.0.0.99", 1),
	}))

	got, total, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID, Keyword: "scan"},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "scan ILIKE 匹配 2 个 URL")
	require.Len(t, got, 2)
}

func TestAsset_List_Pagination(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	rows := make([]*domain.Asset, 0, 7)
	for i := 0; i < 7; i++ {
		rows = append(rows, newAsset(fix, domain.KindHost, "10.1.0."+itoaS(i), 1))
	}
	require.NoError(t, fix.repo.UpsertBulk(ctx, rows))

	page1, total, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID},
		Page{Page: 1, PageSize: 3})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, page1, 3)

	page3, _, err := fix.repo.List(ctx,
		Filter{TenantID: fix.tenantID},
		Page{Page: 3, PageSize: 3})
	require.NoError(t, err)
	require.Len(t, page3, 1, "7 行 / 3 大小 → 第 3 页 1 条")
}

func TestAsset_List_TenantIsolation(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()

	// 当前 tenant 一条
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.10.1", 1),
	}))
	// 第二个 tenant 直接 SQL 插一行（绕过 fixture 的 default tenant 字段）
	var p3 string
	require.NoError(t, fix.pool.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, name) VALUES ($1::uuid, 'isolated') RETURNING id::text`,
		fix.tenantID2).Scan(&p3))

	a := &domain.Asset{
		TenantID: fix.tenantID2, ProjectID: p3,
		Kind: domain.KindHost, Value: "10.0.10.1", ResultCount: 1,
	}
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{a}))

	got, total, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "另一个 tenant 的同 value 不应可见")
	require.Len(t, got, 1)
	assert.Equal(t, fix.tenantID, got[0].TenantID)
}

// === GetByID ===

func TestAsset_GetByID_Roundtrip(t *testing.T) {
	fix := setupAssetRepo(t)
	ctx := context.Background()
	require.NoError(t, fix.repo.UpsertBulk(ctx, []*domain.Asset{
		newAsset(fix, domain.KindHost, "10.0.20.1", 2),
	}))
	got, _, err := fix.repo.List(ctx, Filter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	require.Len(t, got, 1)

	a, err := fix.repo.GetByID(ctx, got[0].ID)
	require.NoError(t, err)
	assert.Equal(t, got[0].ID, a.ID)
	assert.Equal(t, "10.0.20.1", a.Value)
	assert.Equal(t, 2, a.ResultCount)
}

func TestAsset_GetByID_NotFound(t *testing.T) {
	fix := setupAssetRepo(t)
	_, err := fix.repo.GetByID(context.Background(),
		"00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAssetNotFound, c)
}

func TestAsset_GetByID_EmptyRejected(t *testing.T) {
	fix := setupAssetRepo(t)
	_, err := fix.repo.GetByID(context.Background(), "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === local helper ===

// itoaS 本测试文件内的轻量数字 → 字符串（避免 strconv import 与 pg.go 内部
// itoa 重名冲突；这里只用作 IP octet 拼装）。
func itoaS(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	out := ""
	for n > 0 {
		out = string(digits[n%10]) + out
		n /= 10
	}
	return out
}
