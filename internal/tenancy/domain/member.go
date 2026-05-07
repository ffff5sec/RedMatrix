package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// ProjectMember 是 project_members 表的领域映射（LLD 11 §3.3 / §5）。
//
// 不变式：
//   - 同一用户在同一项目只能有一行（schema PRIMARY KEY 强制）
//   - tenant_id 必须 == project.tenant_id == user.tenant_id（service 层校验）
//   - 仅 ProjectAdmin 角色可作为成员（service 校验，schema 不强制以保留演进弹性）
type ProjectMember struct {
	ProjectID string
	UserID    string
	TenantID  string
	AddedBy   string // 可空：用户硬删后保留 nullable
	AddedAt   time.Time
}

// ValidateForCreate 在 repo.Add 前调一遍域内规则。
//
// 不查 user.role —— service 层调用前应先 GetByID(user) 校验 role==ProjectAdmin。
// 这里只校结构合法性。
func (m *ProjectMember) ValidateForCreate() error {
	if m == nil {
		return errx.New(errx.ErrInvalidInput, "member is nil")
	}
	if m.ProjectID == "" {
		return errx.New(errx.ErrInvalidInput, "member.project_id 不能为空")
	}
	if m.UserID == "" {
		return errx.New(errx.ErrInvalidInput, "member.user_id 不能为空")
	}
	if m.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "member.tenant_id 不能为空")
	}
	return nil
}
