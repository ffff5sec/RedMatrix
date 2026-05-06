package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// APIKeyRepository 是 api_keys 表的持久层接口（LLD 10 §8）。
//
// 错误约定：
//   - GetByID / FindByPrefix 找不到 → ErrAPIKeyNotFound
//   - 其他 DB 故障 → ErrDatabase 包装
//
// 写入约定：
//   - Insert 要求 k.ValidateForCreate 已通过；返回时回填 k.ID（若为 ""）+ k.CreatedAt
//   - Revoke 写 revoked_at = now()；幂等（已撤销的再调一遍仍 noop 成功）
//   - UpdateLastUsed 把 last_used_at 刷成 now()；用于 Auth 路径 best-effort
type APIKeyRepository interface {
	// Insert 写入新 key 行。
	Insert(ctx context.Context, k *domain.APIKey) error

	// GetByID 按 UUID 查；找不到 → ErrAPIKeyNotFound。
	GetByID(ctx context.Context, id string) (*domain.APIKey, error)

	// FindByPrefix 按 8 字符 prefix 查（UNIQUE 索引 O(1)）；找不到 → ErrAPIKeyNotFound。
	// Auth 路径 hot path：解析 raw token → 提取 prefix → 此方法。
	FindByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error)

	// ListByUser 列出该用户全部 key（含已撤销 / 已过期），created_at DESC。
	// 调用方按 IsUsable 过滤"可用"。
	ListByUser(ctx context.Context, userID string) ([]*domain.APIKey, error)

	// Revoke 写 revoked_at = now()。已撤销的再调一遍仍成功（幂等）。
	// 行不存在 → ErrAPIKeyNotFound。
	Revoke(ctx context.Context, id string) error

	// UpdateLastUsed 把 last_used_at 刷为 now()。
	// 行不存在 → ErrAPIKeyNotFound。
	UpdateLastUsed(ctx context.Context, id string) error
}
