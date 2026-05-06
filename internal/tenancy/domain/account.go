// Package domain 是 tenancy 模块的纯领域类型 + 业务规则（不依赖 repo / proto / RPC）。
//
// 对应 docs/LLD/11-tenancy-module.md §3。
package domain

import (
	"regexp"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// AccountStatus 是租户状态机 3 状态之一。
type AccountStatus string

const (
	AccountActive    AccountStatus = "active"
	AccountSuspended AccountStatus = "suspended"
	AccountDisabled  AccountStatus = "disabled"
)

// Valid 判断 AccountStatus 是否合法值。
func (s AccountStatus) Valid() bool {
	switch s {
	case AccountActive, AccountSuspended, AccountDisabled:
		return true
	}
	return false
}

// Account 是 tenancy 模块的核心实体（LLD 11 §3.1）。字段映射 accounts 表。
type Account struct {
	ID          string
	Slug        string
	DisplayName string
	Plan        string
	Status      AccountStatus

	QuotaUsers    int
	QuotaProjects int
	QuotaAssets   int64

	Settings map[string]any // 解码自 settings jsonb

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time // 软删；MVP 暂不暴露 RPC
}

// IsActive Status==active 且未软删。
func (a *Account) IsActive() bool {
	return a != nil && a.Status == AccountActive && a.DeletedAt == nil
}

// slug 规则：3-32 字符，小写字母 / 数字 / 连字符（与 schema CHECK 一致）。
var slugRe = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (a *Account) ValidateForCreate() error {
	if a == nil {
		return errx.New(errx.ErrInvalidInput, "account is nil")
	}
	if !slugRe.MatchString(a.Slug) {
		return errx.New(errx.ErrInvalidInput,
			"slug 必须 3-32 字符（小写字母 / 数字 / 连字符）").
			WithFields("got", a.Slug)
	}
	if a.DisplayName == "" {
		return errx.New(errx.ErrInvalidInput, "display_name 不能为空")
	}
	if len(a.DisplayName) > 128 {
		return errx.New(errx.ErrInvalidInput, "display_name 超出最大长度 128")
	}
	if a.Status == "" {
		a.Status = AccountActive
	}
	if !a.Status.Valid() {
		return errx.New(errx.ErrInvalidInput, "status 不合法").
			WithFields("got", string(a.Status))
	}
	if a.Plan == "" {
		a.Plan = "standard"
	}
	return nil
}
