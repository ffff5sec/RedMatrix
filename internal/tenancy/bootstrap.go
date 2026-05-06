// Package tenancy 顶层包当前承载 Bootstrap：首次启动落地默认 account。
//
// 子包：
//   - domain：聚合 + 不变式
//   - repo：PG 持久层
//
// 后续 PR 会加：
//   - service：业务流（Project / Member / Node CRUD）
//   - handler：ConnectRPC 适配
//
// Bootstrap 设计（LLD 11 §3.1 注：MVP 默认 1 个 active account；
// 部署期插入而非运行时 RPC 创建）。
package tenancy

import (
	"context"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// DefaultAccountID 是 bootstrap 期间使用的固定 UUID（前端 / 集成测试可硬编码）。
//
// 选用全 0 末位 1 形式：
//   - 显眼可识别
//   - 与 gen_random_uuid() 产出空间不重叠（实际不可能撞）
//   - 多次 reset 后 ID 不变，便于跨运行验证
const DefaultAccountID = "00000000-0000-0000-0000-000000000001"

// DefaultAccountSlug / DisplayName 是默认租户的标识。
const (
	DefaultAccountSlug        = "default"
	DefaultAccountDisplayName = "RedMatrix"
)

// BootstrapConfig 是 Bootstrap 的入参。
//
// 留扩展位（自定义 slug / display_name）但 MVP 总是用默认值。
type BootstrapConfig struct {
	Slug        string // 空 → "default"
	DisplayName string // 空 → "RedMatrix"
	FixedID     string // 空 → DefaultAccountID
}

// BootstrapResult 是 Bootstrap 返回信息。
type BootstrapResult struct {
	Created bool            // 本次新建 vs 已存在 skipped
	Account *domain.Account // 始终非 nil（创建或加载）
}

// Bootstrap 落地默认 account（幂等）。
//
// 流程：
//  1. GetBySlug(slug) → 存在即跳过返结果（幂等）
//  2. 不存在 → Insert（用 FixedID 让 UUID 跨运行稳定）
//
// 错误：
//   - DB 故障 → ErrDatabase（透传 repo）
//   - slug 重复（理论不可能，因为前置 GetBySlug 已查）→ ErrAccountSlugExists
func Bootstrap(ctx context.Context, accounts repo.AccountRepository, cfg BootstrapConfig) (*BootstrapResult, error) {
	if accounts == nil {
		return nil, errx.New(errx.ErrInternal, "Bootstrap: accounts repo 不能为 nil")
	}
	if strings.TrimSpace(cfg.Slug) == "" {
		cfg.Slug = DefaultAccountSlug
	}
	if strings.TrimSpace(cfg.DisplayName) == "" {
		cfg.DisplayName = DefaultAccountDisplayName
	}
	if strings.TrimSpace(cfg.FixedID) == "" {
		cfg.FixedID = DefaultAccountID
	}

	// 1. 幂等检查
	existing, err := accounts.GetBySlug(ctx, cfg.Slug)
	if err == nil {
		return &BootstrapResult{Created: false, Account: existing}, nil
	}
	if !isAccountNotFound(err) {
		return nil, err
	}

	// 2. 不存在 → 创建
	a := &domain.Account{
		ID:          cfg.FixedID,
		Slug:        cfg.Slug,
		DisplayName: cfg.DisplayName,
		Plan:        "standard",
		Status:      domain.AccountActive,
	}
	if err := accounts.Insert(ctx, a); err != nil {
		return nil, err
	}
	return &BootstrapResult{Created: true, Account: a}, nil
}

func isAccountNotFound(err error) bool {
	c, ok := errx.GetCode(err)
	if !ok {
		return false
	}
	return c == errx.ErrAccountNotFound
}
