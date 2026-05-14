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
	// markExistingOnUpsert true 时 UpsertBulkReturning 返 IsNew=false（已存在）
	markExistingOnUpsert bool
	stubRepoFields
}

type stubRepoFields struct {
	upserted [][]*domain.Asset // 每次 UpsertBulk 的 batch
	rows     []*domain.Asset
	byID     map[string]*domain.Asset
	// 记录 List 时的 filter / page 让测试断言 RBAC 注入
	lastFilter repo.Filter
	lastPage   repo.Page
	listErr    error
	// PR-S59 disappeared sweep
	markDisappearedReturn []*domain.Asset
	markDisappearedCalls  int
}

func newStubRepo() *stubRepo {
	return &stubRepo{stubRepoFields: stubRepoFields{byID: map[string]*domain.Asset{}}}
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

// UpsertBulkReturning PR-S57 stub：把全部 item 视作新插入（is_new=true）；
// 真 PG 实现按冲突区分。测试用 stub 简单返一一对应结果。
func (r *stubRepo) UpsertBulkReturning(ctx context.Context, items []*domain.Asset) ([]*repo.UpsertResult, error) {
	if err := r.UpsertBulk(ctx, items); err != nil {
		return nil, err
	}
	out := make([]*repo.UpsertResult, len(items))
	for i, it := range items {
		out[i] = &repo.UpsertResult{Asset: it, IsNew: !r.markExistingOnUpsert}
	}
	return out, nil
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

// MarkDisappeared PR-S59 stub：返 markDisappearedReturn 中的资产，并把它们的
// LastSeen 视为已超 cutoff（测试 setup 已塞好）；二次调返空模拟幂等。
func (r *stubRepo) MarkDisappeared(_ context.Context, _ time.Time) ([]*domain.Asset, error) {
	out := r.markDisappearedReturn
	r.markDisappearedCalls++
	r.markDisappearedReturn = nil // 模拟幂等：再扫不再返
	return out, nil
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

// === PR-S57 资产事件触发 ===

// stubEventRepo 收集所有 InsertBulk 的事件。
type stubEventRepo struct {
	inserted          []*domain.Event
	insertBulk        []*domain.Event
	err               error
	sweepCertsResult  []*domain.Event
	sweepCertsCalls   int
	lastCertWindow    time.Duration
	lastCertDedupeWin time.Duration
}

func (s *stubEventRepo) Insert(_ context.Context, e *domain.Event) error {
	if s.err != nil {
		return s.err
	}
	s.inserted = append(s.inserted, e)
	return nil
}
func (s *stubEventRepo) InsertBulk(_ context.Context, events []*domain.Event) error {
	if s.err != nil {
		return s.err
	}
	s.insertBulk = append(s.insertBulk, events...)
	return nil
}
func (s *stubEventRepo) List(_ context.Context, _ repo.EventFilter, _ repo.Page) ([]*domain.Event, int, error) {
	return nil, 0, nil
}
func (s *stubEventRepo) GetByID(_ context.Context, _ string) (*domain.Event, error) {
	return nil, nil
}
func (s *stubEventRepo) SweepCertsExpiring(_ context.Context, window, dedupeWindow time.Duration) ([]*domain.Event, error) {
	s.sweepCertsCalls++
	s.lastCertWindow = window
	s.lastCertDedupeWin = dedupeWindow
	if s.err != nil {
		return nil, s.err
	}
	return s.sweepCertsResult, nil
}

// TestUpsertFromResults_TriggersNewAssetEvents：新插入 subdomain / host / url
// 三种资产，每种派生对应事件 kind。
func TestUpsertFromResults_TriggersNewAssetEvents(t *testing.T) {
	r := newStubRepo()
	ev := &stubEventRepo{}
	svc, err := NewServiceWithEvents(r, ev, nil)
	require.NoError(t, err)
	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "sub.example.com"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "10.0.0.1"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "web_crawl", Data: map[string]any{"url": "https://example.com/login"}},
	}))
	if len(ev.insertBulk) != 3 {
		t.Fatalf("want 3 events, got %d: %+v", len(ev.insertBulk), ev.insertBulk)
	}
	// 验证 kind 映射
	kinds := map[domain.EventKind]bool{}
	for _, e := range ev.insertBulk {
		kinds[e.Kind] = true
	}
	for _, want := range []domain.EventKind{
		domain.EventNewSubdomain, domain.EventNewPort, domain.EventNewService,
	} {
		if !kinds[want] {
			t.Errorf("missing event kind: %s", want)
		}
	}
}

// TestUpsertFromResults_ExistingAssetsNoEvent：is_new=false 的 asset 不派事件。
func TestUpsertFromResults_ExistingAssetsNoEvent(t *testing.T) {
	r := newStubRepo()
	r.markExistingOnUpsert = true // stub 把全部当 update
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	_ = svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "sub.example.com"}},
	})
	if len(ev.insertBulk) != 0 {
		t.Errorf("已存在的资产不应派事件，got %d", len(ev.insertBulk))
	}
}

// TestUpsertFromResults_NilEventRepo_NoEventNoError：未注入 EventRepository
// 时走旧 UpsertBulk 路径，无事件无错误。
func TestUpsertFromResults_NilEventRepo_NoEventNoError(t *testing.T) {
	r := newStubRepo()
	svc, _ := NewService(r, nil) // events 不注入
	err := svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "x.example.com"}},
	})
	require.NoError(t, err)
}

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

// === PR-S59 sweeper ===

// TestSweepDisappeared_EmitsEventsForMarked：repo.MarkDisappeared 返几条，
// service 就派同数 disappeared 事件。
func TestSweepDisappeared_EmitsEventsForMarked(t *testing.T) {
	r := newStubRepo()
	r.markDisappearedReturn = []*domain.Asset{
		{ID: "a-1", TenantID: "t1", ProjectID: "p1", Kind: domain.KindSubdomain, Value: "old.example.com", LastSeen: time.Now().Add(-30 * 24 * time.Hour)},
		{ID: "a-2", TenantID: "t1", ProjectID: "p1", Kind: domain.KindHost, Value: "10.0.0.99", LastSeen: time.Now().Add(-20 * 24 * time.Hour)},
	}
	ev := &stubEventRepo{}
	svc, err := NewServiceWithEvents(r, ev, nil)
	require.NoError(t, err)

	n, err := svc.SweepDisappeared(context.Background(), 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	require.Len(t, ev.insertBulk, 2)
	for _, e := range ev.insertBulk {
		assert.Equal(t, domain.EventDisappeared, e.Kind)
		assert.NotNil(t, e.AssetID)
		assert.Contains(t, e.Payload, "asset_value")
		assert.Contains(t, e.Payload, "last_seen")
	}
}

// TestSweepDisappeared_NoneMarked_NoEvents：repo 返空，service 不调 events。
func TestSweepDisappeared_NoneMarked_NoEvents(t *testing.T) {
	r := newStubRepo() // markDisappearedReturn = nil
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)

	n, err := svc.SweepDisappeared(context.Background(), 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Empty(t, ev.insertBulk)
}

// TestSweepDisappeared_NoEventsRepo_NoOp：未注入 EventRepository 时 sweep 应 no-op。
func TestSweepDisappeared_NoEventsRepo_NoOp(t *testing.T) {
	r := newStubRepo()
	r.markDisappearedReturn = []*domain.Asset{
		{ID: "a-1", TenantID: "t1", ProjectID: "p1", Kind: domain.KindHost, Value: "x"},
	}
	svc, _ := NewService(r, nil)
	n, err := svc.SweepDisappeared(context.Background(), 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Zero(t, r.markDisappearedCalls, "未注入 events 时 sweep 不应调 repo")
}

// TestSweepDisappeared_NonPositiveThreshold_NoOp：threshold ≤ 0 防误调。
func TestSweepDisappeared_NonPositiveThreshold_NoOp(t *testing.T) {
	r := newStubRepo()
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	n, err := svc.SweepDisappeared(context.Background(), 0)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Zero(t, r.markDisappearedCalls)
}

// TestSweepCertsExpiring_DelegatesToEventRepo：service 透传到 events 层。
func TestSweepCertsExpiring_DelegatesToEventRepo(t *testing.T) {
	r := newStubRepo()
	fakeEvents := make([]*domain.Event, 7)
	for i := range fakeEvents {
		fakeEvents[i] = &domain.Event{Kind: domain.EventCertExpiring}
	}
	ev := &stubEventRepo{sweepCertsResult: fakeEvents}
	svc, _ := NewServiceWithEvents(r, ev, nil)

	n, err := svc.SweepCertsExpiring(context.Background(), 30*24*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 7, n)
	assert.Equal(t, 1, ev.sweepCertsCalls)
	assert.Equal(t, 30*24*time.Hour, ev.lastCertWindow)
	assert.Equal(t, 7*24*time.Hour, ev.lastCertDedupeWin)
}

// TestSweepCertsExpiring_NoEventsRepo_NoOp：未注入 events 时 no-op。
func TestSweepCertsExpiring_NoEventsRepo_NoOp(t *testing.T) {
	r := newStubRepo()
	svc, _ := NewService(r, nil)
	n, err := svc.SweepCertsExpiring(context.Background(), 30*24*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// TestSweepCertsExpiring_NonPositiveWindow_NoOp。
func TestSweepCertsExpiring_NonPositiveWindow_NoOp(t *testing.T) {
	r := newStubRepo()
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	n, err := svc.SweepCertsExpiring(context.Background(), 0, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Zero(t, ev.sweepCertsCalls)
}

// === PR-S61 AssetEventNotifier ===

type stubNotifier struct {
	calls   int
	batches [][]*domain.Event
}

func (n *stubNotifier) OnAssetEvents(_ context.Context, events []*domain.Event) {
	n.calls++
	n.batches = append(n.batches, events)
}

// TestNotifier_TriggeredOnUpsertNewAssets：UpsertFromResults 新插入 3 资产 →
// notifier 收到 3 事件。
func TestNotifier_TriggeredOnUpsertNewAssets(t *testing.T) {
	r := newStubRepo()
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	notifier := &stubNotifier{}
	WithNotifier(svc, notifier)

	require.NoError(t, svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "x.example.com"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "port_scan", Data: map[string]any{"host": "10.0.0.1"}},
		{TenantID: "t1", ProjectID: "p1", Kind: "web_crawl", Data: map[string]any{"url": "https://x.example.com/"}},
	}))
	require.Equal(t, 1, notifier.calls)
	require.Len(t, notifier.batches[0], 3)
}

// TestNotifier_NotTriggeredOnExisting：UPDATE 路径（IsNew=false）notifier 不调。
func TestNotifier_NotTriggeredOnExisting(t *testing.T) {
	r := newStubRepo()
	r.markExistingOnUpsert = true
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	notifier := &stubNotifier{}
	WithNotifier(svc, notifier)

	_ = svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "x.example.com"}},
	})
	assert.Zero(t, notifier.calls)
}

// TestNotifier_TriggeredOnSweepDisappeared。
func TestNotifier_TriggeredOnSweepDisappeared(t *testing.T) {
	r := newStubRepo()
	r.markDisappearedReturn = []*domain.Asset{
		{ID: "a-1", TenantID: "t1", ProjectID: "p1", Kind: domain.KindHost, Value: "10.0.0.99", LastSeen: time.Now().Add(-30 * 24 * time.Hour)},
	}
	ev := &stubEventRepo{}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	notifier := &stubNotifier{}
	WithNotifier(svc, notifier)

	n, err := svc.SweepDisappeared(context.Background(), 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	require.Equal(t, 1, notifier.calls)
	require.Len(t, notifier.batches[0], 1)
	assert.Equal(t, domain.EventDisappeared, notifier.batches[0][0].Kind)
}

// TestNotifier_TriggeredOnSweepCertsExpiring。
func TestNotifier_TriggeredOnSweepCertsExpiring(t *testing.T) {
	r := newStubRepo()
	fake := []*domain.Event{{Kind: domain.EventCertExpiring}, {Kind: domain.EventCertExpiring}}
	ev := &stubEventRepo{sweepCertsResult: fake}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	notifier := &stubNotifier{}
	WithNotifier(svc, notifier)

	n, err := svc.SweepCertsExpiring(context.Background(), 30*24*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	require.Equal(t, 1, notifier.calls)
	assert.Len(t, notifier.batches[0], 2)
}

// TestNotifier_NotTriggeredWhenEventInsertFails：events.InsertBulk 失败时不应调 notifier
// （未真正落库的事件不发通知）。
func TestNotifier_NotTriggeredWhenEventInsertFails(t *testing.T) {
	r := newStubRepo()
	ev := &stubEventRepo{err: errx.New(errx.ErrDatabase, "fail")}
	svc, _ := NewServiceWithEvents(r, ev, nil)
	notifier := &stubNotifier{}
	WithNotifier(svc, notifier)

	_ = svc.UpsertFromResults(context.Background(), []ResultInput{
		{TenantID: "t1", ProjectID: "p1", Kind: "subdomain", Data: map[string]any{"name": "x.example.com"}},
	})
	assert.Zero(t, notifier.calls, "事件未落库则不发通知")
}
