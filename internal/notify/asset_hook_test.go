package notify

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	assetdomain "github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// stubNotifySvc 只实现 Notify；其它方法 panic（被调即测试 bug）。
type stubNotifySvc struct {
	captured []Event
	err      error
}

func (s *stubNotifySvc) Notify(_ context.Context, ev Event) error {
	if s.err != nil {
		return s.err
	}
	s.captured = append(s.captured, ev)
	return nil
}

func (s *stubNotifySvc) CreateSubscription(_ context.Context, _ CreateSubscriptionRequest) (*domain.Subscription, error) {
	panic("unexpected")
}
func (s *stubNotifySvc) ListSubscriptions(_ context.Context, _ ListSubscriptionsRequest) (*ListSubscriptionsResult, error) {
	panic("unexpected")
}
func (s *stubNotifySvc) GetSubscription(_ context.Context, _ string) (*domain.Subscription, error) {
	panic("unexpected")
}
func (s *stubNotifySvc) UpdateSubscription(_ context.Context, _ UpdateSubscriptionRequest) (*domain.Subscription, error) {
	panic("unexpected")
}
func (s *stubNotifySvc) DeleteSubscription(_ context.Context, _ string) error {
	panic("unexpected")
}
func (s *stubNotifySvc) TestSubscription(_ context.Context, _ string) error {
	panic("unexpected")
}
func (s *stubNotifySvc) ListDeliveries(_ context.Context, _ ListDeliveriesRequest) (*ListDeliveriesResult, error) {
	panic("unexpected")
}

func TestAssetHook_MapsAllFiveKindsAndCallsNotify(t *testing.T) {
	svc := &stubNotifySvc{}
	h := NewAssetHook(svc, nil)
	pid1 := "p1"
	pid2 := "p2"
	aid := "a-99"
	events := []*assetdomain.Event{
		{ID: "e1", TenantID: "t1", ProjectID: "p1", AssetID: &aid, Kind: assetdomain.EventNewSubdomain, Payload: map[string]any{"asset_value": "sub.example.com"}},
		{ID: "e2", TenantID: "t1", ProjectID: "p1", AssetID: &aid, Kind: assetdomain.EventNewPort, Payload: map[string]any{}},
		{ID: "e3", TenantID: "t1", ProjectID: "p1", AssetID: &aid, Kind: assetdomain.EventNewService, Payload: map[string]any{}},
		{ID: "e4", TenantID: "t1", ProjectID: "p2", AssetID: &aid, Kind: assetdomain.EventDisappeared, Payload: map[string]any{"last_seen": "x"}},
		{ID: "e5", TenantID: "t1", ProjectID: "p2", AssetID: nil, Kind: assetdomain.EventCertExpiring, Payload: map[string]any{"fingerprint": "abc"}},
	}
	h.OnAssetEvents(context.Background(), events)
	require.Len(t, svc.captured, 5)

	wantKinds := []domain.EventKind{
		domain.EventAssetNewSubdomain,
		domain.EventAssetNewPort,
		domain.EventAssetNewService,
		domain.EventAssetDisappeared,
		domain.EventCertExpiring,
	}
	for i, want := range wantKinds {
		assert.Equal(t, want, svc.captured[i].Kind, "kind[%d]", i)
		assert.Equal(t, "t1", svc.captured[i].TenantID)
		assert.Equal(t, events[i].ID, svc.captured[i].Payload["event_id"], "event_id passthrough")
	}
	// project_id 透传
	assert.Equal(t, pid1, *svc.captured[0].ProjectID)
	assert.Equal(t, pid2, *svc.captured[4].ProjectID)
	// AssetID nil → payload 不含 asset_id
	_, hasAssetID := svc.captured[4].Payload["asset_id"]
	assert.False(t, hasAssetID, "AssetID nil 时 payload 不应含 asset_id")
	// topic 拼接
	assert.Equal(t, "asset.event.asset_new_subdomain.v1", svc.captured[0].Topic)
}

func TestAssetHook_NilSvc_NoPanic(t *testing.T) {
	var h *AssetHook
	h.OnAssetEvents(context.Background(), []*assetdomain.Event{{ID: "x", Kind: assetdomain.EventDisappeared}})
	// 不应 panic；nil hook 静默丢弃
}

func TestAssetHook_NotifyError_LoggedNotPanicked(t *testing.T) {
	svc := &stubNotifySvc{err: errors.New("boom")}
	h := NewAssetHook(svc, nil)
	h.OnAssetEvents(context.Background(), []*assetdomain.Event{
		{ID: "e1", TenantID: "t1", ProjectID: "p1", Kind: assetdomain.EventNewSubdomain, Payload: map[string]any{}},
	})
	// 不应 panic；err 静默
}

func TestAssetHook_UnknownKindSkipped(t *testing.T) {
	svc := &stubNotifySvc{}
	h := NewAssetHook(svc, nil)
	h.OnAssetEvents(context.Background(), []*assetdomain.Event{
		{ID: "e1", TenantID: "t1", ProjectID: "p1", Kind: assetdomain.EventKind("unknown_kind"), Payload: map[string]any{}},
	})
	assert.Empty(t, svc.captured, "未知 kind 应跳过，不调 Notify")
}
