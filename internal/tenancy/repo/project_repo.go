package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// ProjectRepository 是 projects 表的持久层接口（LLD 11 §3.2）。
//
// 错误约定：
//   - GetByID 找不到 / 已 soft-deleted → ErrProjectNotFound
//   - Insert name 在租户内重复 → ErrProjectNameExists
//   - 其他 DB 故障 → ErrDatabase 包装
type ProjectRepository interface {
	// Insert 写入新 project 行；要求 p.ValidateForCreate 已通过。
	Insert(ctx context.Context, p *domain.Project) error

	// GetByID 按 UUID 查；不返回已软删的行。
	GetByID(ctx context.Context, id string) (*domain.Project, error)

	// List 列租户内项目（排除 soft-deleted），分页 + 状态过滤。
	// tenantID 空 = SuperAdmin / TenantAuditor 跨租户查（MVP 单租户演示价值低）。
	List(ctx context.Context, filter ProjectFilter, page Page) ([]*domain.Project, int, error)

	// Archive 把状态置 archived + archived_at = now()。幂等：已 archived 不报错。
	Archive(ctx context.Context, id string) error

	// Unarchive 把状态置 active + archived_at = NULL。幂等。
	Unarchive(ctx context.Context, id string) error

	// SoftDelete 把 deleted_at = now()；后续查询全部排除。
	// MVP 不级联 cascade（任务 / 资产 / 节点白名单）；后续 PR 接 LLD 11 §4.4。
	SoftDelete(ctx context.Context, id string) error
}

// ProjectFilter 是 List 查询的可选过滤条件。
type ProjectFilter struct {
	TenantID string               // 空 = 跨租户
	Status   domain.ProjectStatus // 空 = 不过滤
	Keyword  string               // 空 = 不过滤；name ILIKE 子串
}

// Page 分页参数；与 identity/repo.Page 对偶但模块独立（演进可分歧）。
type Page struct {
	Page     int
	PageSize int
}
