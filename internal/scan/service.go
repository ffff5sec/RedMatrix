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
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan/repo"
	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// ProjectLookup 是 scan service 的最小 tenancy 依赖：仅校项目存在 + 同租户。
//
// 故意不直接 import tenancy/repo.ProjectRepository（避免互依赖膨胀）；
// 上层 wire 时把 tenancyrepo.NewProjectPG(...) 注进来即可——它已自然满足该签名。
type ProjectLookup interface {
	GetByID(ctx context.Context, id string) (*tenancydomain.Project, error)
}

// NodeLister 列租户内节点（PR-S2 调度用：选 online 子集）。
//
// 与 tenancyrepo.NodeRepository.List 同签名；wire 时直接注入。
type NodeLister interface {
	List(ctx context.Context, filter tenancyrepo.NodeFilter, page tenancyrepo.Page) ([]*tenancydomain.Node, int, error)
}

// AllowedNodesLookup 取项目可用节点白名单。
type AllowedNodesLookup interface {
	Get(ctx context.Context, projectID string) (tenancydomain.AllowedNodes, error)
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

	// ListAssignmentsByTask 详情页用：列任务全部派发单（PR-S2）。
	ListAssignmentsByTask(ctx context.Context, taskID string) ([]*domain.TaskAssignment, error)

	// CountAssignmentsByTaskIDs 列表页一次性拉所有 task 的派发计数（PR-S2）。
	CountAssignmentsByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error)

	// PullForNode（PR-S3 mTLS）：把 nodeID 名下 status='assigned' 的派发单
	// 原子置 'pulled' 并返；幂等，agent 多次调安全。
	PullForNode(ctx context.Context, nodeID string) ([]*PulledAssignment, error)

	// UpdateAssignmentProgress（PR-S3 mTLS）：agent 上报进度。
	// 校 assignment.node_id == callerNodeID（防伪造）+ 状态机合法。
	// status 仅允许 running / completed / failed。
	UpdateAssignmentProgress(ctx context.Context, callerNodeID, assignmentID string, status domain.AssignmentStatus, errMsg string) error

	// ReportResults（PR-S5 mTLS）：agent 上报扫描结果。
	// 校 assignment.node_id == callerNodeID 防伪造；data schema-less。
	ReportResults(ctx context.Context, callerNodeID, assignmentID string, items []ResultItem) error

	// ListResultsByTask（PR-S5 详情页）：列任务全部结果。SA / TA / PA 都可调
	// （PA 仅看自己加入的项目；MVP 不在 service 层强制 PA 限制）。
	ListResultsByTask(ctx context.Context, taskID string) ([]*domain.ScanResult, error)
}

// ResultItem 是 ReportResults 入参；service 内部组合 task/assignment/node id 后入库。
type ResultItem struct {
	Data map[string]any
}

// PulledAssignment 是 PullForNode 返的轻封装：assignment 元数据 + 关联的 task
// 描述（kind / target / target_kind / project_id），让 Agent 一次拿全。
type PulledAssignment struct {
	AssignmentID string
	TaskID       string
	ProjectID    string
	Kind         domain.TaskKind
	Target       string
	TargetKind   domain.TargetKind
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
	tasks       repo.TaskRepository
	assignments repo.AssignmentRepository
	results     repo.ResultRepository
	projects    ProjectLookup
	nodes       NodeLister
	allowed     AllowedNodesLookup
	logger      *log.Logger
	now         func() time.Time
}

// NewService 构造 scan Service；任一依赖 nil 时返 ErrInternal（logger 可空）。
func NewService(
	tasks repo.TaskRepository,
	assignments repo.AssignmentRepository,
	results repo.ResultRepository,
	projects ProjectLookup,
	nodes NodeLister,
	allowed AllowedNodesLookup,
	logger *log.Logger,
) (Service, error) {
	if tasks == nil || assignments == nil || results == nil || projects == nil || nodes == nil || allowed == nil {
		return nil, errx.New(errx.ErrInternal, "scan.NewService: 依赖不能为 nil")
	}
	return &service{
		tasks: tasks, assignments: assignments, results: results,
		projects: projects, nodes: nodes, allowed: allowed,
		logger: logger, now: time.Now,
	}, nil
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

	// PR-S2 同步派发：项目 allowed_nodes ∩ 租户内 online 节点 → InsertBulk。
	// 派发失败仅日志（task 已建，UI 详情页可见 0 派发；运维可手动 Cancel + 重建）。
	if err := s.dispatch(ctx, t); err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "scan.dispatch failed", err,
				"task_id", t.ID, "project_id", t.ProjectID)
		}
	}
	return t, nil
}

// dispatch 把 task 派发到项目允许 ∩ 租户在线节点。零节点不返错（task 仍建）。
func (s *service) dispatch(ctx context.Context, t *domain.ScanTask) error {
	allowed, err := s.allowed.Get(ctx, t.ProjectID)
	if err != nil {
		return err
	}
	// 显式白名单 + 空 NodeIDs = "暂时禁所有" → 不派发
	if allowed.IsExplicitWhitelist() && len(allowed.NodeIDs) == 0 {
		return nil
	}

	nodes, _, err := s.nodes.List(ctx,
		tenancyrepo.NodeFilter{TenantID: t.TenantID, Status: tenancydomain.NodeOnline},
		tenancyrepo.Page{Page: 1, PageSize: 200})
	if err != nil {
		return err
	}
	now := s.now()
	picked := make([]*domain.TaskAssignment, 0, len(nodes))
	for _, n := range nodes {
		// DeriveStatus 让"持久化 online + 心跳过期"展示成 offline，避免派给已离线
		if n.DeriveStatus(now) != tenancydomain.NodeOnline {
			continue
		}
		if !allowed.Contains(n.ID) {
			continue
		}
		picked = append(picked, &domain.TaskAssignment{
			TaskID: t.ID, NodeID: n.ID, Status: domain.AssignmentAssigned,
		})
	}
	if len(picked) == 0 {
		return nil
	}
	return s.assignments.InsertBulk(ctx, picked)
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

func (s *service) ListAssignmentsByTask(ctx context.Context, taskID string) ([]*domain.TaskAssignment, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "task_id 不能为空")
	}
	return s.assignments.ListByTask(ctx, taskID)
}

func (s *service) CountAssignmentsByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error) {
	if len(taskIDs) == 0 {
		return map[string]int{}, nil
	}
	return s.assignments.CountByTaskIDs(ctx, taskIDs)
}

// PullForNode（PR-S3）—— assigned → pulled 原子翻转 + 取关联 task 元数据。
//
// 不直接 INNER JOIN 是为了让 repo 接口保持纯 assignments；这里 N+1 但
// MVP 一次 pull 数量 < 50（agent 不会堆积），影响可忽略。
func (s *service) PullForNode(ctx context.Context, nodeID string) ([]*PulledAssignment, error) {
	if strings.TrimSpace(nodeID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "pull 缺 node_id")
	}
	pulled, err := s.assignments.PullForNode(ctx, nodeID)
	if err != nil {
		return nil, err
	}
	// 收集涉及到的 taskID（去重）→ aggregator 推 pending → running
	touched := make(map[string]struct{}, len(pulled))
	out := make([]*PulledAssignment, 0, len(pulled))
	for _, a := range pulled {
		t, err := s.tasks.GetByID(ctx, a.TaskID)
		if err != nil {
			// task 软删但 assignment 还在 → 跳过（agent 不需做这种孤儿）
			if s.logger != nil {
				s.logger.Warn("pull: skip orphan assignment",
					"assignment_id", a.ID, "task_id", a.TaskID, "err", err.Error())
			}
			continue
		}
		out = append(out, &PulledAssignment{
			AssignmentID: a.ID,
			TaskID:       t.ID,
			ProjectID:    t.ProjectID,
			Kind:         t.Kind,
			Target:       t.Target,
			TargetKind:   t.TargetKind,
		})
		touched[t.ID] = struct{}{}
	}
	// PR-S4 task 聚合（pending → running）
	for tID := range touched {
		if err := s.aggregateTaskStatus(ctx, tID); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: aggregate after pull failed", err, "task_id", tID)
		}
	}
	return out, nil
}

// UpdateAssignmentProgress（PR-S3）—— 状态机推进 + 防伪造校验。
//
// PR-S4：成功后跑 task 聚合（推 task.status pending → running → completed/failed）。
func (s *service) UpdateAssignmentProgress(
	ctx context.Context,
	callerNodeID, assignmentID string,
	status domain.AssignmentStatus,
	errMsg string,
) error {
	if strings.TrimSpace(callerNodeID) == "" {
		return errx.New(errx.ErrInvalidInput, "缺 caller node_id")
	}
	if strings.TrimSpace(assignmentID) == "" {
		return errx.New(errx.ErrInvalidInput, "缺 assignment_id")
	}
	switch status {
	case domain.AssignmentRunning, domain.AssignmentCompleted, domain.AssignmentFailed:
	default:
		return errx.New(errx.ErrTaskInvalidState,
			"status 必须是 running / completed / failed").
			WithFields("got", string(status))
	}
	a, err := s.assignments.GetByID(ctx, assignmentID)
	if err != nil {
		return err
	}
	if a.NodeID != callerNodeID {
		return errx.New(errx.ErrTaskNotFound, "assignment 不属于此节点（防伪造）").
			WithFields("assignment_id", a.ID)
	}
	if a.Status.IsTerminal() {
		return errx.New(errx.ErrTaskInvalidState, "终态不可再转").
			WithFields("current", string(a.Status))
	}
	if err := s.assignments.UpdateStatus(ctx, assignmentID, status, errMsg); err != nil {
		return err
	}

	// PR-S4 task 聚合：失败仅日志，不影响 agent 报进度的成功语义
	if err := s.aggregateTaskStatus(ctx, a.TaskID); err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "scan: aggregate task status failed", err,
				"task_id", a.TaskID, "assignment_id", assignmentID)
		}
	}
	return nil
}

// aggregateTaskStatus（PR-S4）—— 根据该 task 全部 assignments 推算 task.status。
//
// 规则（与 UI 默认 chip 颜色对齐）：
//   - 0 assignments：保持 task 原状态（一般 pending；CancelTask 主动改的 canceled 不动）
//   - 任一 assignment ∈ {running, pulled}：task = running
//   - 全部终态：
//   - 任一 failed                           → task = failed
//   - 任一 completed（可能混 canceled）       → task = completed
//   - 全 canceled                          → 保持原状态（assignments 极少全 canceled，
//     而且 task 本身的 canceled 状态由 CancelTask 主动写）
//   - 否则（全 assigned；agent 还没拉）：task = pending
//
// task 终态后不再改（caller 不会触发——agents 不能 update 已 terminal 的 assignment）。
func (s *service) aggregateTaskStatus(ctx context.Context, taskID string) error {
	t, err := s.tasks.GetByID(ctx, taskID)
	if err != nil {
		return err
	}
	// task 已经被 CancelTask 主动取消，或已落终态 → 不再 aggregator 写
	if t.Status == domain.TaskCanceled || t.Status.IsTerminal() {
		return nil
	}

	list, err := s.assignments.ListByTask(ctx, taskID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return nil
	}

	allTerminal, anyRunningOrPulled, anyFailed, anyCompleted := true, false, false, false
	for _, a := range list {
		switch a.Status {
		case domain.AssignmentAssigned:
			allTerminal = false
		case domain.AssignmentPulled, domain.AssignmentRunning:
			allTerminal = false
			anyRunningOrPulled = true
		case domain.AssignmentCompleted:
			anyCompleted = true
		case domain.AssignmentFailed:
			anyFailed = true
		}
	}

	var next domain.TaskStatus
	switch {
	case anyRunningOrPulled:
		next = domain.TaskRunning
	case allTerminal && anyFailed:
		next = domain.TaskFailed
	case allTerminal && anyCompleted:
		next = domain.TaskCompleted
	case allTerminal:
		// 全 canceled — 极少发生；保持 task 原状态
		return nil
	default:
		// 全 assigned，agent 还没拉
		next = domain.TaskPending
	}

	if next == t.Status {
		return nil
	}

	var finishedAt *string
	if next.IsTerminal() {
		ts := s.now().UTC().Format(time.RFC3339)
		finishedAt = &ts
	}
	return s.tasks.UpdateStatus(ctx, taskID, next, finishedAt)
}

// ReportResults（PR-S5）—— 防伪造校验 + bulk insert。
//
// 校 assignment 存在 + a.NodeID == callerNodeID；从 assignment 反推 task_id；
// 从 task 拿 kind 一并入库。空 items 直接 no-op。
func (s *service) ReportResults(
	ctx context.Context,
	callerNodeID, assignmentID string,
	items []ResultItem,
) error {
	if strings.TrimSpace(callerNodeID) == "" {
		return errx.New(errx.ErrInvalidInput, "缺 caller node_id")
	}
	if strings.TrimSpace(assignmentID) == "" {
		return errx.New(errx.ErrInvalidInput, "缺 assignment_id")
	}
	if len(items) == 0 {
		return nil
	}
	a, err := s.assignments.GetByID(ctx, assignmentID)
	if err != nil {
		return err
	}
	if a.NodeID != callerNodeID {
		return errx.New(errx.ErrTaskNotFound, "assignment 不属于此节点（防伪造）").
			WithFields("assignment_id", a.ID)
	}
	t, err := s.tasks.GetByID(ctx, a.TaskID)
	if err != nil {
		return err
	}
	rows := make([]*domain.ScanResult, 0, len(items))
	for _, it := range items {
		rows = append(rows, &domain.ScanResult{
			TaskID:       t.ID,
			AssignmentID: a.ID,
			NodeID:       a.NodeID,
			Kind:         t.Kind,
			Data:         it.Data,
		})
	}
	return s.results.InsertBulk(ctx, rows)
}

// ListResultsByTask（PR-S5）—— 详情页直查。
func (s *service) ListResultsByTask(ctx context.Context, taskID string) ([]*domain.ScanResult, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "缺 task_id")
	}
	return s.results.ListByTask(ctx, taskID)
}
