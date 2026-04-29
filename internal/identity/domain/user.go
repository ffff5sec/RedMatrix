// Package domain 是 identity 模块的纯领域类型 + 业务规则（不依赖 repo / proto / RPC）。
//
// 对应 docs/LLD/10-identity-module.md §4 / 01 §1.2.1。
//
// 设计原则：
//   - 纯类型 + 纯规则：不发起 IO；可在 unit 测试里完整跑过
//   - 错误统一走 errx.DomainError（ErrInvalidInput / ErrInvalidFormat 等）
//   - 时区：所有时间字段以 UTC 存储；展示由前端按用户时区渲染
package domain

import (
	"regexp"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Role 是平台 4 个独立角色之一（与 docs/UX/01-roles.md / proto Role enum 对齐）。
type Role string

const (
	RoleSuperAdmin      Role = "SUPER_ADMIN"
	RoleProjectAdmin    Role = "PROJECT_ADMIN"
	RoleTenantAuditor   Role = "TENANT_AUDITOR"
	RolePlatformAuditor Role = "PLATFORM_AUDITOR" // Phase 2
)

// Valid 判断 Role 是否合法值。
func (r Role) Valid() bool {
	switch r {
	case RoleSuperAdmin, RoleProjectAdmin, RoleTenantAuditor, RolePlatformAuditor:
		return true
	}
	return false
}

// IsCrossTenant 跨租户角色（SuperAdmin / PlatformAuditor）；其他角色必须有 tenant_id。
func (r Role) IsCrossTenant() bool {
	return r == RoleSuperAdmin || r == RolePlatformAuditor
}

// Status 是用户状态机 3 状态之一。
type Status string

const (
	StatusActive          Status = "active"
	StatusDisabled        Status = "disabled"
	StatusPendingDeletion Status = "pending_deletion"
)

// Valid 判断 Status 是否合法值。
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusDisabled, StatusPendingDeletion:
		return true
	}
	return false
}

// User 是 identity 模块的核心实体。字段映射 users 表（migrate 0004）。
type User struct {
	ID                 string
	TenantID           string // 空字串 = 跨租户（SuperAdmin / PlatformAuditor）
	Username           string
	PasswordHash       string // argon2id PHC string；明文密码绝不入此结构
	Email              string // 可选
	Role               Role
	Status             Status
	TokenVersion       int  // JWT 失效计数（10 §5.4）
	MustChangePassword bool // bootstrap admin 首登强制改密

	LastLoginAt time.Time // zero = 从未登录
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// 用户名规则（10 §4.3）：3-32 字符，小写字母 / 数字 / 下划线 / 连字符。
// 拒绝大写、空格、@、点等容易混淆的字符。
var usernameRe = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

// 邮箱：宽松校验（仅形态：local@domain.tld）。生产应配合发邮件验证 / DNS MX 查。
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ValidateForCreate 跑 INSERT 前的全部域内规则（不查 DB）。
func (u *User) ValidateForCreate() error {
	if u == nil {
		return errx.New(errx.ErrInvalidInput, "user is nil")
	}
	if !usernameRe.MatchString(u.Username) {
		return errx.New(errx.ErrInvalidInput,
			"username 必须 3-32 字符（小写字母 / 数字 / 下划线 / 连字符）").
			WithFields("got", u.Username)
	}
	if u.Email != "" && !emailRe.MatchString(u.Email) {
		return errx.New(errx.ErrInvalidFormat, "email 格式不合法").
			WithFields("got", u.Email)
	}
	if !u.Role.Valid() {
		return errx.New(errx.ErrInvalidInput, "role 不合法").
			WithFields("got", string(u.Role))
	}
	if u.Status == "" {
		u.Status = StatusActive
	}
	if !u.Status.Valid() {
		return errx.New(errx.ErrInvalidInput, "status 不合法").
			WithFields("got", string(u.Status))
	}
	if strings.TrimSpace(u.PasswordHash) == "" {
		return errx.New(errx.ErrInvalidInput,
			"password_hash 不能为空（请先 HashPassword 后再 Create）")
	}
	return u.ValidateTenantConsistency()
}

// ValidateTenantConsistency 与 PG CHECK 约束 users_tenant_role_consistency 等价的应用层校验。
//
// SuperAdmin / PlatformAuditor 必须 TenantID="";
// ProjectAdmin / TenantAuditor 必须 TenantID 非空。
//
// 应用层先校验避免无意义往返 DB。
func (u *User) ValidateTenantConsistency() error {
	if u.Role.IsCrossTenant() && u.TenantID != "" {
		return errx.New(errx.ErrInvalidInput,
			"跨租户角色不应携带 tenant_id").
			WithFields("role", string(u.Role), "tenant_id", u.TenantID)
	}
	if !u.Role.IsCrossTenant() && u.TenantID == "" {
		return errx.New(errx.ErrInvalidInput,
			"非跨租户角色必须指定 tenant_id").
			WithFields("role", string(u.Role))
	}
	return nil
}

// IsActive 是 Status==active 的便利判定（业务代码常用）。
func (u *User) IsActive() bool {
	return u != nil && u.Status == StatusActive
}
