package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// RegistrationToken 是一次性节点注册令牌（LLD 11 §3.7 / §7）。
//
// 关键不变式：
//   - token_hash 是 SHA-256(plaintext) 的 hex（schema CHECK 强制 64 字符 [a-f0-9]）
//   - plaintext 只在创建时一次性返给 SA；不入库
//   - used_at 一经写入不可撤回（单次性）
//   - 与 API Key 不同：节点令牌只用于"首次接入"换取 Node 身份，之后由 mTLS 证书替代
type RegistrationToken struct {
	ID        string
	TenantID  string
	Name      string
	TokenHash string

	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time

	CreatedBy string
	CreatedAt time.Time
}

// 默认 / 上限 TTL。
const (
	RegistrationTokenDefaultTTL = 1 * time.Hour
	RegistrationTokenMaxTTL     = 24 * time.Hour
	RegistrationTokenMinTTL     = 1 * time.Minute
	RegistrationTokenNameMaxLen = 64
)

// IsExpired 当前时刻是否已过期。
func (t *RegistrationToken) IsExpired(now time.Time) bool {
	return t != nil && !t.ExpiresAt.After(now)
}

// IsUsed 是否已兑换。
func (t *RegistrationToken) IsUsed() bool {
	return t != nil && t.UsedAt != nil
}

// IsRevoked 是否被撤销。
func (t *RegistrationToken) IsRevoked() bool {
	return t != nil && t.RevokedAt != nil
}

// IsUsable 仍可兑换：未用 + 未撤 + 未过期。
func (t *RegistrationToken) IsUsable(now time.Time) bool {
	return t != nil && !t.IsUsed() && !t.IsRevoked() && !t.IsExpired(now)
}

// ValidateForCreate 在 repo.Insert 前调一遍域内规则。
func (t *RegistrationToken) ValidateForCreate() error {
	if t == nil {
		return errx.New(errx.ErrInvalidInput, "registration token is nil")
	}
	if t.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "registration_token.tenant_id 不能为空")
	}
	if t.Name == "" {
		return errx.New(errx.ErrInvalidInput, "registration_token.name 不能为空")
	}
	if len(t.Name) > RegistrationTokenNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "registration_token.name 超出最大长度").
			WithFields("max", RegistrationTokenNameMaxLen)
	}
	if len(t.TokenHash) != 64 {
		return errx.New(errx.ErrInvalidInput,
			"registration_token.token_hash 必须 64 字符（SHA-256 hex）")
	}
	if t.ExpiresAt.IsZero() {
		return errx.New(errx.ErrInvalidInput, "registration_token.expires_at 不能为零值")
	}
	return nil
}
