package domain

import (
	"net/netip"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Session 是登录元数据，绑定在 JWT 的 sid claim 上仅用于审计回溯（LLD 10 §3.4 / 7.1）。
//
// 关键约束：
//   - Session 不参与 JWT 吊销判定（吊销靠 user.token_version）
//   - 单 session 下线 MVP 不做（41-security 决策）
//   - "全部下线" = user.token_version+1 + sessions 全部 expires_at=now()（仅 UI 同步）
type Session struct {
	ID           string
	TenantID     string // "" 表示 SuperAdmin / PlatformAuditor 跨租户
	UserID       string
	UserAgent    string
	IP           netip.Addr // 零值表示未知 IP
	IssuedAt     time.Time
	LastSeenAt   time.Time
	TokenVersion int
	ExpiresAt    time.Time
}

// IsExpired 判断 session 是否已过期（now ≥ ExpiresAt）。
func (s *Session) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now)
}

// ValidateForCreate 在 repo.Create 之前调一遍域内规则。
func (s *Session) ValidateForCreate() error {
	if s == nil {
		return errx.New(errx.ErrInvalidInput, "session is nil")
	}
	if s.UserID == "" {
		return errx.New(errx.ErrInvalidInput, "session.user_id 不能为空")
	}
	if s.TokenVersion < 0 {
		return errx.New(errx.ErrInvalidInput, "session.token_version 不能为负")
	}
	if s.IssuedAt.IsZero() {
		return errx.New(errx.ErrInvalidInput, "session.issued_at 不能为零值")
	}
	if s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) {
		return errx.New(errx.ErrInvalidInput, "session.expires_at 必须 > issued_at")
	}
	return nil
}
