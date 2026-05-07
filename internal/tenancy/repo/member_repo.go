package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// ProjectMemberRepository 是 project_members 表的持久层接口。
//
// 错误约定：
//   - Add 重复 → ErrProjectMemberExists
//   - Remove 行不存在 → ErrProjectMemberNotFound
//   - 其他 DB 故障 → ErrDatabase 包装
type ProjectMemberRepository interface {
	// Add 加入成员；要求 m.ValidateForCreate 已通过。
	Add(ctx context.Context, m *domain.ProjectMember) error

	// Remove 删除成员（按复合键）。行不存在返 ErrProjectMemberNotFound。
	Remove(ctx context.Context, projectID, userID string) error

	// Exists 查复合键是否存在；service ListProjects PA 路径用。
	Exists(ctx context.Context, projectID, userID string) (bool, error)

	// ListByProject 列项目成员（按 added_at ASC）。
	ListByProject(ctx context.Context, projectID string) ([]*domain.ProjectMember, error)

	// ListProjectIDsByUser 列用户加入的所有项目 ID。
	// PA ListProjects 路径用：先取 ID 集合，再按 ID 列项目本体。
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}
