package tenancy

import (
	"context"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// Service 是 tenancy 模块的业务流接口。
//
// PR-T2 范围：Project CRUD（不含成员 / 节点 / 白名单）。
// Authz（角色检查）由 handler 层做；service 不查 caller role。
type Service interface {
	// CreateProject 在租户内创建项目。name 在租户内唯一（活项目）。
	CreateProject(ctx context.Context, req CreateProjectRequest) (*domain.Project, error)

	// ListProjects 列租户内项目；分页 + 过滤。
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
}

// NewService 构造 tenancy Service。
func NewService(projects repo.ProjectRepository) (Service, error) {
	if projects == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.NewService: projects repo 不能为 nil")
	}
	return &service{projects: projects}, nil
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
