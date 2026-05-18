// Package repo 是 asset 模块持久层接口（PR-S8）。
package repo

import (
	"context"
	"time"

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

	// UpsertBulkReturning PR-S57：UPSERT + 返回真正新插入的 asset（带 ID）。
	// SQL 用 RETURNING id, (xmax = 0) AS is_new 区分插入 vs 更新；service 层
	// 据 is_new=true 派生 asset_events。空切片返 nil/nil。
	//
	// 返回的 asset 顺序与输入一致；非新插入的位置返 nil（caller filter nil 取
	// 真新增列表）。
	UpsertBulkReturning(ctx context.Context, items []*domain.Asset) ([]*UpsertResult, error)

	// List 按过滤条件分页列资产。
	List(ctx context.Context, f Filter, p Page) ([]*domain.Asset, int, error)

	// GetByID 单条；不存在返 ErrAssetNotFound。
	GetByID(ctx context.Context, id string) (*domain.Asset, error)

	// MarkDisappeared PR-S59：把 last_seen < cutoff AND disappeared_at IS NULL
	// 的资产打上 disappeared_at = now()，返回真正被标记的行（用于派事件）。
	// 单 UPDATE ... RETURNING；幂等：再次调同 cutoff 不会重复返。
	// 资产 UPSERT（被重新扫到）会把 disappeared_at reset 成 NULL。
	MarkDisappeared(ctx context.Context, cutoff time.Time) ([]*domain.Asset, error)
}

// UpsertResult UpsertBulkReturning 单条结果。
type UpsertResult struct {
	Asset *domain.Asset // 含真正的 ID（新插入或既有）
	IsNew bool          // true = 本次 INSERT；false = 已存在 UPDATE
}

// Filter List 过滤条件。
type Filter struct {
	TenantID  string
	ProjectID string
	Kind      domain.Kind
	Keyword   string // value 模糊匹配（ILIKE %kw%）
	// Value PR-S70：精确等值匹配（用于 LookupByHost 等）。与 Keyword 同时存在
	// 时 SQL 用 AND，几乎肯定空 result，caller 应只用一个。
	Value string
	// ProjectIDs PA 权限收紧：非 nil 时用 ANY 过滤。空切片 caller 应短路。
	ProjectIDs []string
	// LastSeenBefore（PR-S31 freshness）：非 nil → SQL last_seen < $X；
	// 用于过滤"多久未扫到的资产"。nil = 不过滤。
	LastSeenBefore *time.Time
}

// Page 分页。
type Page struct {
	Page     int // 1-based
	PageSize int // ≤200
}
