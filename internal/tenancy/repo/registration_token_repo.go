package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// RegistrationTokenRepository 是 registration_tokens 表的持久层接口（LLD 11 §3.7 / §7）。
//
// 错误约定：
//   - GetByHash 找不到 → ErrNodeRegistrationTokenInvalid
//   - 其他 DB 故障 → ErrDatabase 包装
//   - 校"已用 / 已过期 / 已撤"语义在 service 层做（用 IsUsable）
type RegistrationTokenRepository interface {
	// Insert 写入新 token；要求 t.ValidateForCreate 已通过。
	Insert(ctx context.Context, t *domain.RegistrationToken) error

	// GetByHash 按 hash 反查（兑换 hot path）；找不到 → ErrNodeRegistrationTokenInvalid。
	GetByHash(ctx context.Context, hash string) (*domain.RegistrationToken, error)

	// GetByID 按 UUID 查（管理 RPC 用）；找不到 → ErrNodeRegistrationTokenInvalid。
	GetByID(ctx context.Context, id string) (*domain.RegistrationToken, error)

	// ListByTenant 列租户全部 token（含已用 / 已撤），created_at DESC。
	ListByTenant(ctx context.Context, tenantID string) ([]*domain.RegistrationToken, error)

	// Revoke 设 revoked_at = now()；幂等。
	// 行不存在 → ErrNodeRegistrationTokenInvalid。
	Revoke(ctx context.Context, id string) error

	// MarkUsed 设 used_at = now()；用于兑换成功后调用。
	// 已 used / revoked / 不存在 → ErrNodeRegistrationTokenInvalid（避免双花）。
	MarkUsed(ctx context.Context, id string) error
}
