package tenancy

import (
	"context"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// UserLookup 是 service 用来校"被加成员是否合法用户 + 角色 + tenant"的接口。
//
// 故意不直接 import identity/repo.Repository（避免互依赖体积放大）；只取这一个
// 方法。idiomatic 用法：传入 identityrepo.NewPG(...) 自动满足。
type UserLookup interface {
	GetByID(ctx context.Context, id string) (*identitydomain.User, error)
}

// Service 是 tenancy 模块的业务流接口。
//
// PR-T2/T3 范围：Project CRUD + ProjectMember CRUD。
// Authz（角色检查）由 handler 层做；service 不查 caller role。
type Service interface {
	// CreateProject 在租户内创建项目。name 在租户内唯一（活项目）。
	CreateProject(ctx context.Context, req CreateProjectRequest) (*domain.Project, error)

	// ListProjects 列租户内项目；分页 + 过滤。
	// req.MemberUserID 非空 → 仅列该用户加入的项目（PA 视角；handler 注入）。
	ListProjects(ctx context.Context, req ListProjectsRequest) (*ListProjectsResult, error)

	// GetProject 取单个项目（已软删返 NotFound）。
	GetProject(ctx context.Context, id string) (*domain.Project, error)

	// ArchiveProject 归档。幂等。
	ArchiveProject(ctx context.Context, id string) error

	// UnarchiveProject 取消归档。幂等。
	UnarchiveProject(ctx context.Context, id string) error

	// DeleteProject 软删（暂不级联 cascade，留给后续 PR）。
	// 删除后 GetByID/List 都不再可见。
	DeleteProject(ctx context.Context, id string) error

	// AddProjectMember 加成员。
	// service 校：被加用户必须存在 + role==ProjectAdmin + tenant 与项目一致；
	// 重复加 → ErrProjectMemberExists（幂等性留给 caller 决定）。
	AddProjectMember(ctx context.Context, req AddProjectMemberRequest) error

	// RemoveProjectMember 移除成员。
	RemoveProjectMember(ctx context.Context, projectID, userID string) error

	// ListProjectMembers 列项目成员（按 added_at ASC）。
	ListProjectMembers(ctx context.Context, projectID string) ([]*domain.ProjectMember, error)
}

// CreateProjectRequest 入参。
type CreateProjectRequest struct {
	TenantID    string // 由 handler 从 principal.TenantID 注（SuperAdmin 跨租户时由 caller 显式指定）
	Name        string
	Description string
	Settings    map[string]any
	CreatedBy   string // user id；handler 从 principal 注
}

// ListProjectsRequest 入参。
type ListProjectsRequest struct {
	TenantID string               // 空 = 跨租户（SA / TA 用）
	Status   domain.ProjectStatus // 空 = 不过滤
	Keyword  string
	Page     int
	PageSize int

	// MemberUserID 非空 → 仅返回该用户加入的项目（PA 视角；handler 注入
	// principal.UserID）。SA / TA 路径留空。
	MemberUserID string
}

// AddProjectMemberRequest 入参。
type AddProjectMemberRequest struct {
	ProjectID string
	UserID    string
	AddedBy   string // caller user id
}

// ListProjectsResult 返回。
type ListProjectsResult struct {
	Projects []*domain.Project
	Total    int
	Page     int
	PageSize int
}

// listMaxPageSize / Default。
const (
	listProjectsDefaultPageSize = 20
	listProjectsMaxPageSize     = 200
)

// service 实现 Service。
type service struct {
	projects repo.ProjectRepository
	members  repo.ProjectMemberRepository
	users    UserLookup
}

// NewService 构造 tenancy Service。
//
// users 用于 AddProjectMember 校验目标用户合法（role==ProjectAdmin + tenant 匹配）。
func NewService(
	projects repo.ProjectRepository,
	members repo.ProjectMemberRepository,
	users UserLookup,
) (Service, error) {
	if projects == nil || members == nil || users == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.NewService: 依赖不能为 nil")
	}
	return &service{projects: projects, members: members, users: users}, nil
}

// === CreateProject ===

func (s *service) CreateProject(ctx context.Context, req CreateProjectRequest) (*domain.Project, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "name 不能为空")
	}
	p := &domain.Project{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Settings:    req.Settings,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.projects.Insert(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// === ListProjects ===

func (s *service) ListProjects(ctx context.Context, req ListProjectsRequest) (*ListProjectsResult, error) {
	if req.PageSize <= 0 {
		req.PageSize = listProjectsDefaultPageSize
	}
	if req.PageSize > listProjectsMaxPageSize {
		req.PageSize = listProjectsMaxPageSize
	}
	if req.Page < 1 {
		req.Page = 1
	}

	// MemberUserID 路径（PA 视角）：先取该用户加入的项目 id 集合，再用集合 +
	// 其他过滤条件查全字段。MVP 实现简单：内存过滤；项目数 <= 1k 量级足够。
	if req.MemberUserID != "" {
		joined, err := s.members.ListProjectIDsByUser(ctx, req.MemberUserID)
		if err != nil {
			return nil, err
		}
		if len(joined) == 0 {
			return &ListProjectsResult{Page: req.Page, PageSize: req.PageSize}, nil
		}
		idset := make(map[string]struct{}, len(joined))
		for _, id := range joined {
			idset[id] = struct{}{}
		}

		// 拉所有匹配 filter 的项目（不分页 → 内存按 id 集合过滤 → 再分页）。
		// 数据量小可接受；规模上来后改 IN 查询或 JOIN。
		all, _, err := s.projects.List(ctx,
			repo.ProjectFilter{
				TenantID: req.TenantID,
				Status:   req.Status,
				Keyword:  req.Keyword,
			},
			repo.Page{Page: 1, PageSize: listProjectsMaxPageSize})
		if err != nil {
			return nil, err
		}
		filtered := make([]*domain.Project, 0, len(joined))
		for _, p := range all {
			if _, ok := idset[p.ID]; ok {
				filtered = append(filtered, p)
			}
		}
		total := len(filtered)
		start := (req.Page - 1) * req.PageSize
		end := start + req.PageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		return &ListProjectsResult{
			Projects: filtered[start:end],
			Total:    total,
			Page:     req.Page,
			PageSize: req.PageSize,
		}, nil
	}

	out, total, err := s.projects.List(ctx,
		repo.ProjectFilter{
			TenantID: req.TenantID,
			Status:   req.Status,
			Keyword:  req.Keyword,
		},
		repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListProjectsResult{
		Projects: out,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

// === GetProject ===

func (s *service) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.GetByID(ctx, id)
}

// === Archive / Unarchive / Delete ===

func (s *service) ArchiveProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.Archive(ctx, id)
}

func (s *service) UnarchiveProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.Unarchive(ctx, id)
}

func (s *service) DeleteProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.SoftDelete(ctx, id)
}

// === ProjectMember CRUD ===

// AddProjectMember 校验项目存在 + 用户存在且为 ProjectAdmin + tenant 一致 → Insert。
func (s *service) AddProjectMember(ctx context.Context, req AddProjectMemberRequest) error {
	if strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.UserID) == "" {
		return errx.New(errx.ErrInvalidInput, "project_id / user_id 不能为空")
	}
	p, err := s.projects.GetByID(ctx, req.ProjectID)
	if err != nil {
		return err
	}
	u, err := s.users.GetByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if u.Role != identitydomain.RoleProjectAdmin {
		return errx.New(errx.ErrProjectMemberRoleInvalid,
			"仅 PROJECT_ADMIN 可加入项目").
			WithFields("user_role", string(u.Role))
	}
	if u.TenantID != p.TenantID {
		return errx.New(errx.ErrAuthzTenantMismatch,
			"用户与项目不在同一租户").
			WithFields("user_tenant", u.TenantID, "project_tenant", p.TenantID)
	}
	return s.members.Add(ctx, &domain.ProjectMember{
		ProjectID: p.ID,
		UserID:    u.ID,
		TenantID:  p.TenantID,
		AddedBy:   req.AddedBy,
	})
}

// RemoveProjectMember 移除成员。
func (s *service) RemoveProjectMember(ctx context.Context, projectID, userID string) error {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(userID) == "" {
		return errx.New(errx.ErrInvalidInput, "project_id / user_id 不能为空")
	}
	return s.members.Remove(ctx, projectID, userID)
}

// ListProjectMembers 列项目成员。
func (s *service) ListProjectMembers(ctx context.Context, projectID string) ([]*domain.ProjectMember, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	// 先 GetByID 判存在 → 不存在统一 NotFound（防 ID 枚举借列表 RPC）
	if _, err := s.projects.GetByID(ctx, projectID); err != nil {
		return nil, err
	}
	return s.members.ListByProject(ctx, projectID)
}
