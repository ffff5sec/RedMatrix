// Package repo 是 asset 模块持久层接口（PR-S8）。
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
)

// Repository 资产 CRUD。
type Repository interface {
	// UpsertBulk 把若干 Asset 行批量 UPSERT。
	// 冲突键 (tenant_id, project_id, kind, value) 命中时：
	//   last_seen = greatest(now(), last_seen)
	//   result_count = result_count + delta（caller 在 a.ResultCount 里给增量）
	// 不存在则插入；first_seen / last_seen 初始化为 now()。
	UpsertBulk(ctx context.Context, items []*domain.Asset) error

	// List 按过滤条件分页列资产。
	List(ctx context.Context, f Filter, p Page) ([]*domain.Asset, int, error)

	// GetByID 单条；不存在返 ErrAssetNotFound。
	GetByID(ctx context.Context, id string) (*domain.Asset, error)
}

// Filter List 过滤条件。
type Filter struct {
	TenantID  string
	ProjectID string
	Kind      domain.Kind
	Keyword   string // value 模糊匹配（ILIKE %kw%）
	// ProjectIDs PA 权限收紧：非 nil 时用 ANY 过滤。空切片 caller 应短路。
	ProjectIDs []string
}

// Page 分页。
type Page struct {
	Page     int // 1-based
	PageSize int // ≤200
}
