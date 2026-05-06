package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// ProjectStatus 是项目状态机 2 状态之一（LLD 11 §4.1）。
type ProjectStatus string

const (
	ProjectActive   ProjectStatus = "active"
	ProjectArchived ProjectStatus = "archived"
)

// Valid 判断 ProjectStatus 是否合法值。
func (s ProjectStatus) Valid() bool {
	switch s {
	case ProjectActive, ProjectArchived:
		return true
	}
	return false
}

// ProjectStatsCache 是 projects.stats_cache JSONB 的 typed view。
//
// 由后台任务异步刷新（LLD 11 §3.2）；MVP 仅持久化空对象，刷新逻辑后续 PR。
type ProjectStatsCache struct {
	AssetsTotal  int64     `json:"assets_total,omitempty"`
	TasksTotal   int64     `json:"tasks_total,omitempty"`
	RunningTasks int32     `json:"running_tasks,omitempty"`
	RefreshedAt  time.Time `json:"refreshed_at,omitempty"`
}

// Project 是 tenancy 模块的核心实体（LLD 11 §3.2）。
type Project struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	Status      ProjectStatus

	Settings   map[string]any
	StatsCache ProjectStatsCache

	CreatedBy string // 可空（schema 允许；服务层填 caller user_id）

	CreatedAt  time.Time
	UpdatedAt  time.Time
	ArchivedAt *time.Time
	DeletedAt  *time.Time
}

// IsMutable 是否允许 update/delete（LLD 11 §3.2 末段：归档后只读）。
//
// 限制范围：业务流程中"修改 settings / 改名"等需 IsMutable=true；
// Archive / Unarchive / Delete 是状态变换，独立判定。
func (p *Project) IsMutable() bool {
	return p != nil && p.Status == ProjectActive && p.DeletedAt == nil
}

// IsArchived 已归档（且未删除）。
func (p *Project) IsArchived() bool {
	return p != nil && p.Status == ProjectArchived && p.DeletedAt == nil
}

// IsDeleted 软删后即不可见（任何 RPC 都返 NotFound）。
func (p *Project) IsDeleted() bool {
	return p != nil && p.DeletedAt != nil
}

// ProjectName 长度上限（与 schema VARCHAR(128) 同）。
const ProjectNameMaxLen = 128

// ProjectDescriptionMaxLen 描述上限（与 schema CHECK 同）。
const ProjectDescriptionMaxLen = 2000

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (p *Project) ValidateForCreate() error {
	if p == nil {
		return errx.New(errx.ErrInvalidInput, "project is nil")
	}
	if p.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "project.tenant_id 不能为空")
	}
	if p.Name == "" {
		return errx.New(errx.ErrInvalidInput, "project.name 不能为空")
	}
	if len(p.Name) > ProjectNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "project.name 超出最大长度").
			WithFields("max", ProjectNameMaxLen)
	}
	if len(p.Description) > ProjectDescriptionMaxLen {
		return errx.New(errx.ErrInvalidInput, "project.description 超出最大长度").
			WithFields("max", ProjectDescriptionMaxLen)
	}
	if p.Status == "" {
		p.Status = ProjectActive
	}
	if !p.Status.Valid() {
		return errx.New(errx.ErrInvalidInput, "project.status 不合法").
			WithFields("got", string(p.Status))
	}
	// 状态一致性：Create 总是 active；archived 在 Archive 流程产生
	if p.Status == ProjectActive && p.ArchivedAt != nil {
		return errx.New(errx.ErrInvalidInput, "active 项目不应有 archived_at")
	}
	return nil
}
