package notify

// asset_hook.go —— asset 模块 → notify 模块的桥接（PR-S61）。
//
// asset.AssetEventNotifier 接口由 asset 包定义，我们在这里提供实现。
// asset 包不直接 import notify，避免层次倒挂；cmd/server wire 时手动装配。
//
// 一次 OnAssetEvents 调用对应一次写库的一批事件（≤ 50 条典型）；逐条
// 调 notify.Service.Notify。任一条失败仅 log 继续，不阻断其它通知。

import (
	"context"

	assetdomain "github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// AssetHook 实现 asset.AssetEventNotifier。
type AssetHook struct {
	svc    Service
	logger Logger
}

// NewAssetHook 构造；svc 不可空；logger 可空。
func NewAssetHook(svc Service, logger Logger) *AssetHook {
	return &AssetHook{svc: svc, logger: logger}
}

// OnAssetEvents 实现 asset.AssetEventNotifier；逐条转 notify.Event 并调 svc.Notify。
func (h *AssetHook) OnAssetEvents(ctx context.Context, events []*assetdomain.Event) {
	if h == nil || h.svc == nil {
		return
	}
	for _, ae := range events {
		if ae == nil {
			continue
		}
		kind, ok := mapAssetEventKind(ae.Kind)
		if !ok {
			continue
		}
		ev := Event{
			Kind:      kind,
			TenantID:  ae.TenantID,
			ProjectID: stringPtrOrNil(ae.ProjectID),
			Topic:     "asset.event." + string(ae.Kind) + ".v1",
			Payload:   assetEventPayload(ae),
		}
		if err := h.svc.Notify(ctx, ev); err != nil && h.logger != nil {
			h.logger.LogError(ctx, "notify.AssetHook: notify failed", err,
				"event_id", ae.ID, "event_kind", string(ae.Kind))
		}
	}
}

// mapAssetEventKind asset domain kind → notify kind；字面量一致但走类型转换
// 防未来漂移；不识别返 false 跳过。
func mapAssetEventKind(k assetdomain.EventKind) (domain.EventKind, bool) {
	switch k {
	case assetdomain.EventNewSubdomain:
		return domain.EventAssetNewSubdomain, true
	case assetdomain.EventNewPort:
		return domain.EventAssetNewPort, true
	case assetdomain.EventNewService:
		return domain.EventAssetNewService, true
	case assetdomain.EventDisappeared:
		return domain.EventAssetDisappeared, true
	case assetdomain.EventCertExpiring:
		return domain.EventCertExpiring, true
	}
	return "", false
}

// assetEventPayload 透传 asset event payload + 加 event_id / asset_id。
func assetEventPayload(e *assetdomain.Event) map[string]any {
	out := make(map[string]any, len(e.Payload)+2)
	for k, v := range e.Payload {
		out[k] = v
	}
	out["event_id"] = e.ID
	if e.AssetID != nil && *e.AssetID != "" {
		out["asset_id"] = *e.AssetID
	}
	return out
}

func stringPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
