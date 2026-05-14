// event.go PR-S57 —— 资产变更事件领域模型（SPEC §2.7 MVP 一期）。
//
// 触发时机：
//   - asset_new_* : asset.UpsertFromResults 时新插入资产，按 kind 派生
//     · subdomain kind → asset_new_subdomain
//     · host kind     → asset_new_port（PR-S57：仅资产首次出现）；后续
//     PR 加端口级 diff 时拆分 new_port vs new_service
//   - asset_disappeared : sweeper 定时扫 last_seen 超阈值（PR-S58）
//   - cert_expiring_soon: tls_scan 结果派生（PR-S58）
package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// EventKind 资产事件类型。与 asset_events.event_kind CHECK 同步。
type EventKind string

const (
	EventNewSubdomain EventKind = "asset_new_subdomain"
	EventNewPort      EventKind = "asset_new_port"
	EventNewService   EventKind = "asset_new_service"
	EventDisappeared  EventKind = "asset_disappeared"
	EventCertExpiring EventKind = "cert_expiring_soon"
)

// Valid 校验枚举合法。
func (k EventKind) Valid() bool {
	switch k {
	case EventNewSubdomain, EventNewPort, EventNewService,
		EventDisappeared, EventCertExpiring:
		return true
	}
	return false
}

// Event 资产事件领域实体。
type Event struct {
	ID        string
	TenantID  string
	ProjectID string
	AssetID   *string // 消失类事件 caller 显式置 nil；新增类必填
	Kind      EventKind
	Payload   map[string]any
	CreatedAt time.Time
}

// ValidateForCreate INSERT 前校验。
func (e *Event) ValidateForCreate() error {
	if e == nil {
		return errx.New(errx.ErrInvalidInput, "asset_event is nil")
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "asset_event.tenant_id 不能为空")
	}
	if strings.TrimSpace(e.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "asset_event.project_id 不能为空")
	}
	if !e.Kind.Valid() {
		return errx.New(errx.ErrInvalidInput, "asset_event.kind 不合法").
			WithFields("got", string(e.Kind))
	}
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	return nil
}

// DeriveEventKindForNewAsset 把 asset.Kind 转成"新增类"事件类型。
//
// 映射：
//   - KindSubdomain → EventNewSubdomain
//   - KindHost      → EventNewPort（host 资产首次出现 = 该 host 首次有可达端口）
//   - KindURL       → EventNewService（web_crawl 探到新 URL = 该域首次有 web 服务）
//
// 不识别返 ("", false)。
//
// 注：MVP 简化——port_scan / fingerprint 内部端口 / 协议级 diff 留 PR-S58。
// 当前 host kind 首次出现即派 new_port；后续可在 result.data.port / .service
// 层面做细粒度 diff。
func DeriveEventKindForNewAsset(k Kind) (EventKind, bool) {
	switch k {
	case KindSubdomain:
		return EventNewSubdomain, true
	case KindHost:
		return EventNewPort, true
	case KindURL:
		return EventNewService, true
	}
	return "", false
}
