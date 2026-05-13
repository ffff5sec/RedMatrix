// asset/service_test.go PR-S45 —— 资产 service 单测。
//
// 覆盖：
//   - UpsertFromResults: port_scan→host / subdomain→subdomain / web_crawl→url
//     的派生；同批合并；空切片 no-op；缺字段静默跳过
//   - ListAssets: PA 0 项目短路返空（不查 repo）；PA 传越权 project 拒；
//     RBAC scope 注入 repo Filter；分页归一（page=0 → 1；size=0 → 50；size>200 → 200）
//   - ListAssets: MinAgeDays > 0 → 注 LastSeenBefore cutoff
//   - GetAsset: 空 id 拒；透传
package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/asset/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === stub Repository ===

type stubRepo struct {
	upserted [][]*domain.Asset // 每次 UpsertBulk 的 batch
	rows     []*domain.Asset
	byID     map[string]*domain.Asset
	// 记录 List 时的 filter / page 让测试断言 RBAC 注入
	lastFilter repo.Filter
	lastPage   repo.Page
	listErr    error
}

func newStubRepo() *stubRepo {
	return &stubRepo{byID: map[string]*domain.Asset{}}
}

func (r *stubRepo) UpsertBulk(_ context.Context, items []*domain.Asset) error {
	r.upserted = append(r.upserted, items)
	for _, a := range items {
		if a.ID == "" {
			a.ID = "a-" + string(a.Kind) + "-" + a.Value
		}
		r.rows = append(r.rows, a)
		r.byID[a.ID] = a
	}
	return nil
}
func (r *stubRepo) List(_ context.Context, f repo.Filter, p repo.Page) ([]*domain.Asset, int, error) {
	r.lastFilter = f
	r.lastPage = p
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	out := []*domain.Asset{}
	for _, a := range r.rows {
		if f.TenantID != "" && a.TenantID != f.TenantID {
			continue
		}
		if f.ProjectID != "" && a.ProjectID != f.ProjectID {
			continue
		}
		if f.Kind != "" && a.Kind != f.Kind {
			continue
		}
		out = append(out, a)
	}
	return out, len(out), nil
}
func (r *stubRepo) GetByID(_ context.Context, id string) (*domain.Asset, error) {
	a, ok := r.byID[id]
	if !ok {
		return nil, errx.New(errx.ErrAssetNotFound, "not found")
	}
	return a, nil
}

func newSvc(t *testing.T) (Service, *stubRepo) {
	t.Helper()
	r := newStubRepo()
	svc, err := NewService(r, nil)
	require.NoError(t, err)
	return svc, r
}

// === UpsertFromResults ===

func TestUpsertFromResults_EmptyNoOp(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), nil))
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{}))
	assert.Empty(t, r.upserted)
}

func TestUpsertFromResults_DerivesHostFromPortScan(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "192.0.2.10"}},
	}))
	require.Len(t, r.upserted, 1)
	require.Len(t, r.upserted[0], 1)
	a := r.upserted[0][0]
	assert.Equal(t, domain.KindHost, a.Kind)
	assert.Equal(t, "192.0.2.10", a.Value)
	assert.Equal(t, 1, a.ResultCount)
}

func TestUpsertFromResults_DerivesSubdomain(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "api.example.com"}},
	}))
	require.Len(t, r.upserted[0], 1)
	assert.Equal(t, domain.KindSubdomain, r.upserted[0][0].Kind)
	assert.Equal(t, "api.example.com", r.upserted[0][0].Value)
}

func TestUpsertFromResults_DerivesURL(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "web_crawl", Data: map[string]any{"url": "https://example.com/login"}},
	}))
	require.Len(t, r.upserted[0], 1)
	assert.Equal(t, domain.KindURL, r.upserted[0][0].Kind)
}

// TestUpsertFromResults_MergesDuplicatesInBatch 同批次相同 (tenant,project,kind,value)
// 应合并成一行 + ResultCount=2，不重复 UPSERT。
func TestUpsertFromResults_MergesDuplicatesInBatch(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "10.0.0.1"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "10.0.0.1"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "10.0.0.2"}},
	}))
	require.Len(t, r.upserted, 1)
	assert.Len(t, r.upserted[0], 2, "10.0.0.1 + 10.0.0.2 合并后 2 行")
	for _, a := range r.upserted[0] {
		if a.Value == "10.0.0.1" {
			assert.Equal(t, 2, a.ResultCount)
		}
	}
}

func TestUpsertFromResults_MissingDataField_SkippedSilently(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{}}, // 无 host
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: nil},
	}))
	assert.Empty(t, r.upserted, "全部缺字段 → 无 UpsertBulk 调用")
}

func TestUpsertFromResults_UnknownKind_SkippedSilently(t *testing.T) {
	svc, r := newSvc(t)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "unknown_kind", Data: map[string]any{"host": "x"}},
	}))
	assert.Empty(t, r.upserted)
}

// === ListAssets RBAC ===

// TestListAssets_PAZeroProjects_ShortCircuit PR-S45 BOLA：
// PA scope 切片为空（caller 加入 0 项目）应短路返空，不查 repo。
// 防止 SQL 层 WHERE project_id IN () 退化成"全表"或 SQL 报错。
func TestListAssets_PAZeroProjects_ShortCircuit(t *testing.T) {
	svc, r := newSvc(t)
	// 提前在 repo 塞一条，验证短路后并未读到它
	r.rows = append(r.rows, &domain.Asset{
		ID: "a-1", TenantID: "t1", ProjectID: "p-other", Kind: domain.KindHost, Value: "evil",
	})
	res, err := svc.ListAssets(context.Background(), ListRequest{
		ScopedTenantID:   "t1",
		ScopedProjectIDs: []string{}, // 显式空
		Page:             1, PageSize: 10,
	})
	require.NoError(t, err)
	assert.Empty(t, res.Assets)
	assert.Equal(t, 0, res.Total)
	assert.Empty(t, r.lastFilter.TenantID, "短路时不应调 List")
}

// TestListAssets_PARequestsForbiddenProject 用户传 project_id ∉ ScopedProjectIDs
// 应返 ErrProjectAccessDenied 而非"假装返空"（攻击者枚举防护）。
func TestListAssets_PARequestsForbiddenProject(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.ListAssets(context.Background(), ListRequest{
		ScopedTenantID:   "t1",
		ScopedProjectIDs: []string{"p-mine"},
		ProjectID:        "p-other",
		Page:             1, PageSize: 10,
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectAccessDenied, code)
}

// TestListAssets_PARequestsAllowedProject 项目命中 scope 应放行。
func TestListAssets_PARequestsAllowedProject(t *testing.T) {
	svc, r := newSvc(t)
	_, err := svc.ListAssets(context.Background(), ListRequest{
		ScopedTenantID:   "t1",
		ScopedProjectIDs: []string{"p-mine", "p-also-mine"},
		ProjectID:        "p-mine",
		Page:             1, PageSize: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, "t1", r.lastFilter.TenantID)
	assert.Equal(t, "p-mine", r.lastFilter.ProjectID)
	assert.Equal(t, []string{"p-mine", "p-also-mine"}, r.lastFilter.ProjectIDs)
}

// TestListAssets_SANilScope SA 不限 tenant + 不限项目（ScopedProjectIDs=nil）。
func TestListAssets_SANilScope(t *testing.T) {
	svc, r := newSvc(t)
	_, err := svc.ListAssets(context.Background(), ListRequest{
		Page: 1, PageSize: 10,
	})
	require.NoError(t, err)
	assert.Empty(t, r.lastFilter.TenantID)
	assert.Nil(t, r.lastFilter.ProjectIDs)
}

// TestListAssets_MinAgeDaysInjectsCutoff 验证 MinAgeDays 转成 LastSeenBefore。
func TestListAssets_MinAgeDaysInjectsCutoff(t *testing.T) {
	svc, r := newSvc(t)
	fixedNow := time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC)
	svc.(*service).now = func() time.Time { return fixedNow }

	_, err := svc.ListAssets(context.Background(), ListRequest{
		ScopedTenantID: "t1", MinAgeDays: 7, Page: 1, PageSize: 10,
	})
	require.NoError(t, err)
	require.NotNil(t, r.lastFilter.LastSeenBefore)
	expected := fixedNow.Add(-7 * 24 * time.Hour)
	assert.True(t, r.lastFilter.LastSeenBefore.Equal(expected))
}

// TestListAssets_PaginationNormalization page=0 → 1；size=0 → 50；size>200 → 200。
func TestListAssets_PaginationNormalization(t *testing.T) {
	cases := []struct {
		inPage, inSize     int
		wantPage, wantSize int
	}{
		{0, 0, 1, 50},
		{-1, -1, 1, 50},
		{2, 500, 2, 200},
		{3, 30, 3, 30},
	}
	for _, c := range cases {
		svc, r := newSvc(t)
		_, err := svc.ListAssets(context.Background(), ListRequest{
			ScopedTenantID: "t1", Page: c.inPage, PageSize: c.inSize,
		})
		require.NoError(t, err)
		assert.Equal(t, c.wantPage, r.lastPage.Page, "page in=%d", c.inPage)
		assert.Equal(t, c.wantSize, r.lastPage.PageSize, "size in=%d", c.inSize)
	}
}

// === GetAsset ===

func TestGetAsset_EmptyID_Rejected(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.GetAsset(context.Background(), "  ")
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestGetAsset_PropagatesNotFound(t *testing.T) {
	svc, _ := newSvc(t)
	_, err := svc.GetAsset(context.Background(), "missing")
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAssetNotFound, code)
}
