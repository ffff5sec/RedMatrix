package export

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
)

type stubAssetSvc struct {
	pages []*asset.ListResponse
	calls int
	last  asset.ListRequest
}

func (s *stubAssetSvc) UpsertFromResults(_ context.Context, _ []asset.ResultInput) error {
	return nil
}
func (s *stubAssetSvc) ListAssets(_ context.Context, req asset.ListRequest) (*asset.ListResponse, error) {
	s.last = req
	if s.calls >= len(s.pages) {
		return &asset.ListResponse{Assets: nil}, nil
	}
	out := s.pages[s.calls]
	s.calls++
	return out, nil
}
func (s *stubAssetSvc) GetAsset(_ context.Context, _ string) (*domain.Asset, error) {
	return nil, nil
}
func (s *stubAssetSvc) SweepDisappeared(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}
func (s *stubAssetSvc) SweepCertsExpiring(_ context.Context, _, _ time.Duration) (int, error) {
	return 0, nil
}

func TestAssetsResource_PagesAndMapsAllColumns(t *testing.T) {
	fixedTime := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	svc := &stubAssetSvc{
		pages: []*asset.ListResponse{
			{Assets: []*domain.Asset{
				{ID: "a1", TenantID: "t1", ProjectID: "p1", Kind: domain.KindHost, Value: "10.0.0.1",
					FirstSeen: fixedTime, LastSeen: fixedTime, ResultCount: 3},
				{ID: "a2", TenantID: "t1", ProjectID: "p1", Kind: domain.KindSubdomain, Value: "sub.example.com",
					FirstSeen: fixedTime, LastSeen: fixedTime, ResultCount: 1},
			}},
			// 第二页只有 1 条 < pageSize → 拉完即停
			{Assets: []*domain.Asset{
				{ID: "a3", TenantID: "t1", ProjectID: "p1", Kind: domain.KindURL, Value: "https://example.com/",
					FirstSeen: fixedTime, LastSeen: fixedTime, ResultCount: 1},
			}},
		},
	}
	res := &AssetsResource{Svc: svc, PageSize: 2}
	var rows []Row
	require.NoError(t, res.Stream(context.Background(),
		Scope{TenantID: "t1", Query: map[string][]string{"kind": {"host"}}},
		func(r Row) error { rows = append(rows, r); return nil }))
	require.Len(t, rows, 3)
	assert.Equal(t, "a1", rows[0][0])
	assert.Equal(t, "host", rows[0][3])
	assert.Equal(t, "3", rows[0][7])
	assert.Equal(t, "host", string(svc.last.Kind), "Kind 应从 query 透传")
}

func TestAssetsResource_PaginationStopsAfterShortPage(t *testing.T) {
	svc := &stubAssetSvc{pages: []*asset.ListResponse{
		{Assets: []*domain.Asset{{ID: "a1", TenantID: "t1", ProjectID: "p1", Kind: domain.KindHost, Value: "x"}}},
	}}
	res := &AssetsResource{Svc: svc, PageSize: 100}
	count := 0
	require.NoError(t, res.Stream(context.Background(), Scope{}, func(_ Row) error {
		count++
		return nil
	}))
	assert.Equal(t, 1, count)
	assert.Equal(t, 1, svc.calls, "1 < pageSize 应停拉")
}
