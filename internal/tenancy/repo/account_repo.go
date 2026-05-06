// Package repo 是 tenancy 模块持久层抽象。
//
// 错误约定：
//   - GetByID / GetBySlug 找不到 → ErrAccountNotFound
//   - Insert slug 重复 → ErrAccountSlugExists
//   - 其他 DB 故障 → ErrDatabase 包装
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// AccountRepository 是 accounts 表的持久层接口（LLD 11 §3.1）。
type AccountRepository interface {
	// Insert 写入新 account 行。要求 a.ValidateForCreate 已通过。
	// 若 a.ID 非空，使用该 ID（bootstrap 期固定 UUID 用）；空则 DB 生成。
	// slug 重复 → ErrAccountSlugExists（PG 23505 翻译）。
	Insert(ctx context.Context, a *domain.Account) error

	// GetByID 按 UUID 查；找不到 → ErrAccountNotFound。
	GetByID(ctx context.Context, id string) (*domain.Account, error)

	// GetBySlug 按 slug 查；找不到 → ErrAccountNotFound。
	GetBySlug(ctx context.Context, slug string) (*domain.Account, error)

	// ListActive 列出 deleted_at IS NULL 的 account（不分页；MVP 数据量小）。
	// 排序 created_at ASC（默认 account 永远第一）。
	ListActive(ctx context.Context) ([]*domain.Account, error)
}
