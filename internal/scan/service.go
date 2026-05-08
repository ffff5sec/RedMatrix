// Package scan 是扫描模块的业务流（PR-S1 入口；MVP 仅 Task CRUD）。
//
// 后续 PR：
//
//	PR-S2 task_assignments + dispatcher（项目白名单 → 选 online 节点）
//	PR-S3 NodeAgent.PullTasks / ReportTaskProgress（mTLS 拉任务 / 报进度）
//	PR-S4 task_results / 与 ES 对接
package scan

import (
	"context"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan/repo"
	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// ProjectLookup 是 scan service 的最小 tenancy 依赖：仅校项目存在 + 同租户。
//
// 故意不直接 import tenancy/repo.ProjectRepository（避免互依赖膨胀）；
// 上层 wire 时把 tenancyrepo.NewProjectPG(...) 注进来即可——它已自然满足该签名。
type ProjectLookup interface {
	GetByID(ctx context.Context, id string) (*tenancydomain.Project, error)
}

// Service scan 模块业务流接口。
//
// 所有 RPC 假设 caller 已经过 handler 层 Authz；service 不查 caller role。
type Service interface {
	// CreateTask 创建任务；status 默认 pending。校 project 存在 + 同租户 + 未归档软删。
	CreateTask(ctx context.Context, req CreateTaskRequest) (*domain.ScanTask, error)

	// ListTasks 列任务；分页 + 按 project / status / keyword 过滤。
	ListTasks(ctx context.Context, req ListTasksRequest) (*ListTasksResult, error)

	// GetTask 取单个 task（已软删返 NotFound）。
	GetTask(ctx context.Context, id string) (*domain.ScanTask, error)

	// CancelTask 把 task 状态推到 canceled（仅 pending / running 可）。
	CancelTask(ctx context.Context, id string) error

	// DeleteTask 软删；终态 + 非终态都允许（caller 自负责）。
	DeleteTask(ctx context.Context, id string) error
}

// CreateTaskRequest 入参；handler 从 principal 注 TenantID + CreatedBy。
type CreateTaskRequest struct {
	TenantID     string
	ProjectID    string
	Name         string
	Kind         domain.TaskKind
	Target       string
	TargetKind   domain.TargetKind
	ScheduleKind domain.ScheduleKind // 空 → immediate
	CronExpr     string
	Settings     map[string]any
	CreatedBy    string
}

// ListTasksRequest 入参。
type ListTasksRequest struct {
	TenantID  string // 必填（handler 从 principal 注）
	ProjectID string
	Status    domain.TaskStatus
	Keyword   string
	Page      int
	PageSize  int
}

// ListTasksResult 返回。
type ListTasksResult struct {
	Tasks    []*domain.ScanTask
	Total    int
	Page     int
	PageSize int
}

// service 实现 Service。
type service struct {
	tasks    repo.TaskRepository
	projects ProjectLookup
	now      func() time.Time
}

// NewService 构造 scan Service；任一依赖 nil 时返 ErrInternal。
func NewService(tasks repo.TaskRepository, projects ProjectLookup) (Service, error) {
	if tasks == nil || projects == nil {
		return nil, errx.New(errx.ErrInternal, "scan.NewService: 依赖不能为 nil")
	}
	return &service{tasks: tasks, projects: projects, now: time.Now}, nil
}

// CreateTask: 校 project 存在 + 未归档软删 → INSERT。
//
// req.TenantID 非空时校匹配（PA / TA 必填）；为空时（SA 跨租户）从 project 推。
// task 行的 tenant_id 始终来自 project（避免 caller 伪造）。
func (s *service) CreateTask(ctx context.Context, req CreateTaskRequest) (*domain.ScanTask, error) {
	if strings.TrimSpace(req.ProjectID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	p, err := s.projects.GetByID(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.TenantID) != "" && p.TenantID != req.TenantID {
		return nil, errx.New(errx.ErrProjectAccessDenied, "project 不属于此租户").
			WithFields("project_tenant", p.TenantID, "req_tenant", req.TenantID)
	}
	if p.Status == tenancydomain.ProjectArchived {
		return nil, errx.New(errx.ErrProjectArchived, "归档项目不能创建新任务").
			WithFields("project_id", p.ID)
	}

	t := &domain.ScanTask{
		TenantID:     p.TenantID, // 信任 project 的 tenant
		ProjectID:    req.ProjectID,
		Name:         req.Name,
		Kind:         req.Kind,
		Target:       req.Target,
		TargetKind:   req.TargetKind,
		ScheduleKind: req.ScheduleKind,
		CronExpr:     req.CronExpr,
		Settings:     req.Settings,
		CreatedBy:    req.CreatedBy,
	}
	if err := s.tasks.Insert(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// ListTasks 透传 repo（filter 由 handler 决定）。
func (s *service) ListTasks(ctx context.Context, req ListTasksRequest) (*ListTasksResult, error) {
	tasks, total, err := s.tasks.List(ctx, repo.TaskFilter{
		TenantID:  req.TenantID,
		ProjectID: req.ProjectID,
		Status:    req.Status,
		Keyword:   req.Keyword,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	return &ListTasksResult{
		Tasks: tasks, Total: total, Page: page, PageSize: pageSize,
	}, nil
}

func (s *service) GetTask(ctx context.Context, id string) (*domain.ScanTask, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.tasks.GetByID(ctx, id)
}

func (s *service) CancelTask(ctx context.Context, id string) error {
	t, err := s.tasks.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if !t.CanCancel() {
		return errx.New(errx.ErrTaskInvalidState,
			"当前状态不允许取消（仅 pending / running 可）").
			WithFields("status", string(t.Status))
	}
	now := s.now().UTC().Format(time.RFC3339)
	return s.tasks.UpdateStatus(ctx, id, domain.TaskCanceled, &now)
}

func (s *service) DeleteTask(ctx context.Context, id string) error {
	return s.tasks.SoftDelete(ctx, id)
}
