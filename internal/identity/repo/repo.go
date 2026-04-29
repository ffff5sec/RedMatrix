// Package repo 是 identity 模块持久层抽象。
//
// Repository 接口让 service 层与 PG 实现解耦：将来引入 in-memory mock 测试 / 替换
// 后端时无需改 service。
//
// 错误约定：
//   - GetByXxx 找不到 → *errx.DomainError(ErrUserNotFound)
//   - Create 用户名重复 → *errx.DomainError(ErrUserUsernameExists)
//   - 其他 DB 故障 → *errx.DomainError(ErrDatabase) 包装原错误
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// Repository 是 identity 模块的持久层接口。
type Repository interface {
	// Create 写入新用户。要求 user.ValidateForCreate / TenantConsistency 已通过。
	// 用户名重复 → ErrUserUsernameExists（PG 23505 翻译）。
	Create(ctx context.Context, user *domain.User) error

	// GetByID 按 UUID 字串查；找不到 → ErrUserNotFound。
	GetByID(ctx context.Context, id string) (*domain.User, error)

	// GetByUsername 按 username 查（全局唯一）；找不到 → ErrUserNotFound。
	GetByUsername(ctx context.Context, username string) (*domain.User, error)

	// UpdatePassword 改 password_hash + must_change_password；不动其他字段。
	// 改密自动 token_version++（让旧 JWT 失效，10 §5.4）。
	UpdatePassword(ctx context.Context, id, newHash string, mustChange bool) error

	// UpdateLastLogin 更新 last_login_at = now()（成功登录后调用）。
	UpdateLastLogin(ctx context.Context, id string) error

	// IncrementTokenVersion 强制下线该用户（其所有现存 JWT 失效）。
	// 改密时由 UpdatePassword 内部调；显式强制下线 / 注销 / API key 吊销时也用。
	IncrementTokenVersion(ctx context.Context, id string) error

	// UpdateStatus 切换用户状态（active / disabled / pending_deletion）。
	UpdateStatus(ctx context.Context, id string, status domain.Status) error
}
