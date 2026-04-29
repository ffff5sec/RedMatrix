package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// SessionRepository 是 user_sessions 表的持久层接口。
//
// 错误约定：
//   - GetByID 找不到 → ErrSessionNotFound
//   - 其他 DB 故障 → ErrDatabase 包装
type SessionRepository interface {
	// Create 写入新 session 行；要求 s.ValidateForCreate 已通过。
	// 会回填 s.ID（若入参为 ""）。
	Create(ctx context.Context, s *domain.Session) error

	// GetByID 按 UUID 字串查；找不到 → ErrSessionNotFound。
	GetByID(ctx context.Context, id string) (*domain.Session, error)

	// ListByUser 按 user_id 列出该用户全部 session（含已过期），expires_at DESC。
	// 调用方按 IsExpired(now) 自行过滤"活跃"。
	ListByUser(ctx context.Context, userID string) ([]*domain.Session, error)

	// Delete 按 id 删除单条；返回 ErrSessionNotFound 若行不存在。
	Delete(ctx context.Context, id string) error

	// ExpireAllByUser 把该用户所有未过期 session 的 expires_at 置为 now()。
	// 用于 LogoutAllSessions（与 user.token_version++ 同事务）。
	ExpireAllByUser(ctx context.Context, userID string) error

	// UpdateLastSeen 把指定 session 的 last_seen_at 刷成 now()；
	// 由 Auth interceptor 在每个请求收尾时调（用 best-effort 异步亦可）。
	UpdateLastSeen(ctx context.Context, id string) error
}
