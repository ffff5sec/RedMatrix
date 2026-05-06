package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// APIKey 是脚本 / CI / SDK 的长令牌（LLD 10 §8）。
//
// 与 User 的关系：APIKey 必须挂在某个 User 下，权限 = 该 User 的 Role + scopes 交集。
// 用户 hard-delete 时 ON DELETE CASCADE 一并清掉所有 key（schema 保证）。
//
// 不变式：
//   - PrefixLength=8、SecretHashLength=64（SHA-256 hex）、scopes 永远是数组（DB CHECK）
//   - revoked_at 一经写入不可撤回（重新启用 = 创建新 key）
//   - expires_at 可选；nil = 永不过期
type APIKey struct {
	ID         string
	TenantID   string // "" 表示 owner=SuperAdmin
	UserID     string
	Name       string
	KeyPrefix  string   // 8 字符明文，UI 可见
	SecretHash string   // SHA-256(secret) 64 字符 hex
	Scopes     []string // 空 = 继承 user 全部权限（PR3-A 仅持久；MVP 不强制）
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// APIKey 字段长度常量；与 SQL CHECK / VARCHAR(N) 对齐。
const (
	APIKeyPrefixLength     = 8
	APIKeySecretHashLength = 64
	APIKeyNameMaxLength    = 64
)

// IsRevoked 是否已撤销（revoked_at 非空）。
func (k *APIKey) IsRevoked() bool {
	return k.RevokedAt != nil
}

// IsExpired 是否已过期（now ≥ ExpiresAt）；ExpiresAt 为 nil 表示永不过期。
func (k *APIKey) IsExpired(now time.Time) bool {
	if k.ExpiresAt == nil {
		return false
	}
	return !k.ExpiresAt.After(now)
}

// IsUsable 既未撤销也未过期。Auth 路径用此判定是否放行。
func (k *APIKey) IsUsable(now time.Time) bool {
	return !k.IsRevoked() && !k.IsExpired(now)
}

// ValidateForCreate 在 repo.Insert 前调一遍域内规则。
//
// 检查：
//   - UserID 非空
//   - Name 非空 + 长度 ≤ APIKeyNameMaxLength
//   - KeyPrefix 必须 APIKeyPrefixLength 字符
//   - SecretHash 必须 APIKeySecretHashLength 字符（不查内容是否合法 hex；DB CHECK 兜）
//   - ExpiresAt 若非空必须 > CreatedAt（避免一开始就过期）
func (k *APIKey) ValidateForCreate() error {
	if k == nil {
		return errx.New(errx.ErrInvalidInput, "apikey is nil")
	}
	if k.UserID == "" {
		return errx.New(errx.ErrInvalidInput, "apikey.user_id 不能为空")
	}
	if k.Name == "" {
		return errx.New(errx.ErrInvalidInput, "apikey.name 不能为空")
	}
	if len(k.Name) > APIKeyNameMaxLength {
		return errx.New(errx.ErrInvalidInput, "apikey.name 超出最大长度")
	}
	if len(k.KeyPrefix) != APIKeyPrefixLength {
		return errx.New(errx.ErrInvalidInput, "apikey.key_prefix 长度必须为 8")
	}
	if len(k.SecretHash) != APIKeySecretHashLength {
		return errx.New(errx.ErrInvalidInput, "apikey.secret_hash 长度必须为 64")
	}
	if k.ExpiresAt != nil && !k.CreatedAt.IsZero() && !k.ExpiresAt.After(k.CreatedAt) {
		return errx.New(errx.ErrInvalidInput, "apikey.expires_at 必须 > created_at")
	}
	return nil
}
