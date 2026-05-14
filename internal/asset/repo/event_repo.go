// event_repo.go PR-S57 —— asset_events 持久层接口。
package repo

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
)

// EventFilter ListEvents 过滤条件。
type EventFilter struct {
	TenantID   string
	ProjectID  string
	ProjectIDs []string // PA 路径：非 nil 用 ANY；空切片 caller 短路
	Kind       domain.EventKind
	AssetID    string
	TimeFrom   *time.Time
	TimeTo     *time.Time
}

// EventRepository asset_events 表持久层。
type EventRepository interface {
	// Insert 写入单条事件；caller 已通过 ValidateForCreate。
	Insert(ctx context.Context, e *domain.Event) error

	// InsertBulk 批量写入（service.UpsertFromResults 派多事件时用，少 round trip）。
	// 空切片 no-op；任一行 invalid 整批失败。
	InsertBulk(ctx context.Context, events []*domain.Event) error

	// List 按 filter + 分页列；ORDER BY created_at DESC。
	List(ctx context.Context, filter EventFilter, page Page) ([]*domain.Event, int, error)

	// GetByID 单条；不存在返 ErrAssetNotFound（共用 asset 错码，事件本质上是
	// asset 的衍生数据）。
	GetByID(ctx context.Context, id string) (*domain.Event, error)
}
