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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/eventbus"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan/artifact"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan/indexer"
	"github.com/ffff5sec/RedMatrix/internal/scan/metricsscan"
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

// Indexer 把 scan_results 双写到外部检索（ES）+ 提供 SearchResults 查询能力。
// 可空——dev 不装 ES 时 service 退化成 PG-only（Index 跳过；Search 返 ErrUnavailable）。
//
// 实际类型在 internal/scan/indexer 包。
type Indexer interface {
	Index(ctx context.Context, items []*domain.ScanResult) error
	Search(ctx context.Context, q indexer.SearchQuery) (*indexer.SearchResultPage, error)
}

// AssetDeriver 由 scan service 在 ReportResults 后同步调，把 result 行
// 派生成资产（PR-S8）。可空——dev 不挂 asset 模块时 service 退化成"只写
// scan_results"。失败仅日志，不影响 ReportResults 成功语义。
//
// 实际类型在 internal/asset 包；这里只取最小接口避免循环依赖。
type AssetDeriver interface {
	UpsertFromResults(ctx context.Context, items []AssetResultInput) error
}

// AssetResultInput 是 AssetDeriver 的入参；与 asset.ResultInput 同形，
// 这里独立类型避免 scan 直接 import asset 包。
type AssetResultInput struct {
	TenantID, ProjectID, Kind string
	Data                      map[string]any
}

// Scheduler 是 cron 周期任务调度器（PR-S12）。可空——dev / 测试不挂调度器
// 时 schedule_kind=cron 的 task 仍可创建（下次重启 LoadAll 会装入）。
//
// 实际类型在 internal/scan/scheduler 包。
type Scheduler interface {
	Add(taskID, expr string) error
	Remove(taskID string)
}

// ArtifactStore 大文件 artifact 持久化（PR-S16）。可空——dev / 测试不挂 MinIO
// 时 GetArtifactDownloadURL 返 ErrUnavailable。
type ArtifactStore interface {
	PresignGetURL(ctx context.Context, key string, ttl time.Duration) (string, error)
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

	// SearchResults（PR-S7 全局搜索）—— 走 ES。req 中的 ScopedTenantID /
	// ScopedProjectIDs 由 handler 注入做 RBAC 收紧；service 只做透传 + 校验。
	SearchResults(ctx context.Context, req SearchRequest) (*SearchResultPage, error)

	// TriggerCronTask（PR-S12）—— 由 scheduler 到点时回调；从 taskID 读
	// 模板 task → 复制成 schedule_kind=immediate 的实例 task → 派发。
	// 模板 task 已软删 / 取消时静默跳过（不返错，避免 cron 反复打日志）。
	TriggerCronTask(ctx context.Context, taskID string) error

	// SweepStaleAssignments（PR-S14）—— sweeper 定期调；把 status IN
	// (pulled, running) 且超过 timeout 未上报的 assignment 标 failed，并
	// 触发 task 状态聚合。返已扫数。
	SweepStaleAssignments(ctx context.Context, timeout time.Duration) (int, error)

	// RetryTask（PR-S14）—— 从 failed/canceled task 复制成 immediate 实例
	// 触发 dispatch。pending/running 拒。返新实例 task。
	RetryTask(ctx context.Context, taskID string) (*domain.ScanTask, error)

	// GetArtifactDownloadURL（PR-S16）—— 拿 artifact key 的预签名下载 URL。
	// 调用方在 handler 层做 RBAC + key 校验；service 只签 URL。
	GetArtifactDownloadURL(ctx context.Context, key string) (url string, expires time.Time, err error)
}

// SearchRequest 搜索入参。ScopedTenantID / ScopedProjectIDs 由 handler RBAC 注入：
//   - SA / PlatformAuditor: ScopedTenantID = ""，ScopedProjectIDs = nil（不限）
//   - TA: ScopedTenantID = principal.TenantID
//   - PA: ScopedTenantID = principal.TenantID + ScopedProjectIDs = ListProjectIDsByUser
//     若 PA 加入 0 个项目，service 直接返空（不打 ES）
type SearchRequest struct {
	Keyword   string
	Kind      string
	ProjectID string // 用户主动传的过滤；PA 会与 ScopedProjectIDs 求交（PA 只能看 join 的）
	NodeID    string
	TaskID    string
	TimeFrom  *time.Time
	TimeTo    *time.Time
	Page      int
	PageSize  int

	ScopedTenantID   string
	ScopedProjectIDs []string // nil = 不限项目；非 nil = PA 路径，必须命中
}

// SearchResultPage 搜索分页返。复用 indexer.SearchResultPage 也行，
// 这里独立类型让 scan 公共 API 不直接 leak indexer 类型。
type SearchResultPage struct {
	Items    []*domain.ScanResult
	Total    int
	Page     int
	PageSize int
	Facets   []SearchFacet
}

// SearchFacet 一个聚合维度。
type SearchFacet struct {
	Field   string
	Buckets []SearchFacetBucket
}

// SearchFacetBucket key+count。
type SearchFacetBucket struct {
	Key   string
	Count int
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
	// Targets（PR-S22）：dispatch 切给本 assignment 的 target 子集。
	// 空：agent 退化到 [Target] 单值。非空：agent 循环每个调 plugin。
	Targets    []string
	TargetKind domain.TargetKind
}

// CreateTaskRequest 入参；handler 从 principal 注 TenantID + CreatedBy。
type CreateTaskRequest struct {
	TenantID  string
	ProjectID string
	Name      string
	Kind      domain.TaskKind
	// Target 单目标兼容字段；handler 可只传 Target 走老路径。
	Target string
	// Targets 批量目标（PR-S22）。非空时 service 用 Targets[0] 回填 Target，
	// dispatch 时把 Targets 按 online node 数切片到每个 assignment。
	Targets      []string
	TargetKind   domain.TargetKind
	ScheduleKind domain.ScheduleKind // 空 → immediate
	CronExpr     string
	Settings     map[string]any
	CreatedBy    string
	// SourceTaskID（PR-S15）：service 内部触发路径用，cron trigger / RetryTask
	// 设为模板 / 失败 task 的 ID。handler 不暴露给用户（外部 RPC 不传）。
	SourceTaskID *string
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
	// pool 用于 ReportResults 开 tx（PR-S17-OUTB：InsertBulk + PublishTx 原子）。
	// 可空 — 测试 / scaffold 不挂 PG 时 ReportResults 走非-tx 老路径（best-effort）。
	pool      *pgxpool.Pool
	indexer   Indexer       // 可空
	assets    AssetDeriver  // 可空
	scheduler Scheduler     // 可空
	artifacts ArtifactStore // 可空
	metrics   *metricsscan.Collectors
	logger    *log.Logger
	now       func() time.Time
}

// NewService 构造 scan Service。pool / indexer / assets / scheduler / artifacts /
// logger 可空（pool nil 时 ReportResults 走非-TX 兼容路径）。
// Deps 是 NewService 的依赖集合（PR-S18-A）—— 原 13 位置参 → 命名字段，
// 测试 / wire 不易传错；可空字段在注释里明确标注。
type Deps struct {
	// 必填
	Tasks       repo.TaskRepository
	Assignments repo.AssignmentRepository
	Results     repo.ResultRepository
	Projects    ProjectLookup
	Nodes       NodeLister
	Allowed     AllowedNodesLookup

	// 可空
	Pool      *pgxpool.Pool           // nil → ReportResults 走 legacy 非-TX 路径
	Indexer   Indexer                 // nil → ES 双写 / 搜索禁用
	Assets    AssetDeriver            // nil → 资产派生禁用
	Scheduler Scheduler               // nil → cron 注册禁用（重启 LoadAll 兜底）
	Artifacts ArtifactStore           // nil → 大文件下载禁用
	Metrics   *metricsscan.Collectors // nil → Noop 兜底
	Logger    *log.Logger
}

// NewService 构造 scan Service（PR-S18-A：options pattern）。
func NewService(d Deps) (Service, error) {
	if d.Tasks == nil || d.Assignments == nil || d.Results == nil ||
		d.Projects == nil || d.Nodes == nil || d.Allowed == nil {
		return nil, errx.New(errx.ErrInternal, "scan.NewService: 必填依赖不能为 nil")
	}
	met := d.Metrics
	if met == nil {
		met = metricsscan.Noop()
	}
	return &service{
		tasks: d.Tasks, assignments: d.Assignments, results: d.Results,
		projects: d.Projects, nodes: d.Nodes, allowed: d.Allowed,
		pool:    d.Pool,
		indexer: d.Indexer, assets: d.Assets, scheduler: d.Scheduler, artifacts: d.Artifacts,
		metrics: met,
		logger:  d.Logger, now: time.Now,
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

	// PR-S22：规范化 Target / Targets 关系。
	//   - Targets 非空：去重后写 task.Targets；Target 取 Targets[0]（兼容老 column）
	//   - Targets 空：保持老路径，dispatch 走 [Target] 单值
	targets := dedupTargets(req.Targets)
	target := strings.TrimSpace(req.Target)
	if len(targets) > 0 {
		target = targets[0]
	}
	t := &domain.ScanTask{
		TenantID:     p.TenantID, // 信任 project 的 tenant
		ProjectID:    req.ProjectID,
		Name:         req.Name,
		Kind:         req.Kind,
		Target:       target,
		Targets:      targets,
		TargetKind:   req.TargetKind,
		ScheduleKind: req.ScheduleKind,
		CronExpr:     req.CronExpr,
		Settings:     req.Settings,
		CreatedBy:    req.CreatedBy,
		SourceTaskID: req.SourceTaskID, // PR-S15
	}
	if err := s.tasks.Insert(ctx, t); err != nil {
		return nil, err
	}
	s.metrics.TasksCreated.WithLabelValues(string(t.Kind)).Inc() // PR-S17-OBSV

	// PR-S12：cron 模板注册到 scheduler。失败仅日志，不阻断 task 创建
	// （重启后 LoadAll 会兜底重新装载）。
	if t.ScheduleKind == domain.ScheduleCron && s.scheduler != nil {
		if err := s.scheduler.Add(t.ID, t.CronExpr); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: scheduler.Add failed", err,
				"task_id", t.ID, "expr", t.CronExpr)
		}
	}

	// PR-S2 同步派发：项目 allowed_nodes ∩ 租户内 online 节点 → InsertBulk。
	// cron 模板不立即派发（要等 scheduler 触发产生实例 task）；immediate 才派发。
	if t.ScheduleKind != domain.ScheduleCron {
		if err := s.dispatch(ctx, t); err != nil {
			if s.logger != nil {
				s.logger.LogError(ctx, "scan.dispatch failed", err,
					"task_id", t.ID, "project_id", t.ProjectID)
			}
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
	online := make([]string, 0, len(nodes))
	for _, n := range nodes {
		// DeriveStatus 让"持久化 online + 心跳过期"展示成 offline，避免派给已离线
		if n.DeriveStatus(now) != tenancydomain.NodeOnline {
			continue
		}
		if !allowed.Contains(n.ID) {
			continue
		}
		online = append(online, n.ID)
	}
	if len(online) == 0 {
		return nil
	}

	// PR-S22：把 task.Targets 按 online node 数 round-robin 切片。
	//   - Targets 空：走老路径，每 node 一条空 targets 的 assignment（agent 读 task.target）
	//   - Targets 非空且数量 ≤ online：每 node 拿到的 assignment.targets 长度 0 或 1
	//   - Targets 数量 > online：取模分配，每 node 拿 ceil(N/M) 或 floor(N/M)
	picked := make([]*domain.TaskAssignment, 0, len(online))
	if len(t.Targets) == 0 {
		for _, nid := range online {
			picked = append(picked, &domain.TaskAssignment{
				TaskID: t.ID, NodeID: nid, Status: domain.AssignmentAssigned,
			})
		}
	} else {
		shards := sliceTargets(t.Targets, len(online))
		for i, nid := range online {
			if len(shards[i]) == 0 {
				// 切片为空说明 N < M，给该 node 不派；保持 picked 紧凑
				continue
			}
			picked = append(picked, &domain.TaskAssignment{
				TaskID: t.ID, NodeID: nid, Status: domain.AssignmentAssigned,
				Targets: shards[i],
			})
		}
	}
	if len(picked) == 0 {
		return nil
	}
	return s.assignments.InsertBulk(ctx, picked)
}

// dedupTargets 去空白 / 去重，保持顺序。空 slice → nil。
func dedupTargets(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sliceTargets 把 N 个 target 平均切到 M 个 shard：
//   - N ≥ M：每 shard 至少 floor(N/M)，前 (N%M) 个 shard 多分 1 个
//   - N < M：前 N 个 shard 各拿 1 个，剩 (M-N) 个 shard 空
//
// 这样保证 dispatch 不漏 target；空 shard 的 assignment 由 caller 跳过避免空 task。
func sliceTargets(targets []string, shardCount int) [][]string {
	out := make([][]string, shardCount)
	if shardCount <= 0 || len(targets) == 0 {
		return out
	}
	n := len(targets)
	base := n / shardCount
	extra := n % shardCount
	idx := 0
	for i := 0; i < shardCount; i++ {
		size := base
		if i < extra {
			size++
		}
		if size == 0 {
			out[i] = nil
			continue
		}
		end := idx + size
		if end > n {
			end = n
		}
		out[i] = targets[idx:end]
		idx = end
	}
	return out
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
	if err := s.tasks.UpdateStatus(ctx, id, domain.TaskCanceled, &now); err != nil {
		return err
	}
	s.metrics.TasksTerminal.WithLabelValues(string(domain.TaskCanceled)).Inc() // PR-S17-OBSV
	// PR-S12：cron 模板取消后停止后续触发；幂等，未注册时 no-op。
	if s.scheduler != nil && t.ScheduleKind == domain.ScheduleCron {
		s.scheduler.Remove(id)
	}
	return nil
}

func (s *service) DeleteTask(ctx context.Context, id string) error {
	// PR-S12：先取一次 task 看是否 cron，删后注销 scheduler；
	// 取不到（已软删 / 不存在）由 SoftDelete 自己返错，这里静默继续。
	var isCron bool
	if t, err := s.tasks.GetByID(ctx, id); err == nil && t.ScheduleKind == domain.ScheduleCron {
		isCron = true
	}
	if err := s.tasks.SoftDelete(ctx, id); err != nil {
		return err
	}
	if isCron && s.scheduler != nil {
		s.scheduler.Remove(id)
	}
	return nil
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
		// PR-S22：优先用 assignment.Targets（dispatch 切片结果）；
		// 退化 1：assignment.Targets 空但 task.Targets 非空 → 把 task 全量发下去
		//   （兜底；正常 dispatch 后 assignment.Targets 不会为空）
		// 退化 2：都为空 → agent 仍读 task.Target 单值
		targets := a.Targets
		if len(targets) == 0 && len(t.Targets) > 0 {
			targets = append([]string(nil), t.Targets...)
		}
		out = append(out, &PulledAssignment{
			AssignmentID: a.ID,
			TaskID:       t.ID,
			ProjectID:    t.ProjectID,
			Kind:         t.Kind,
			Target:       t.Target,
			Targets:      targets,
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
	// PR-S17-RACE：原子化 — WHERE 子句一次性校 node_id（防伪造）+ 非终态
	// （防 TOCTOU 并发覆盖）。失败统一 NotFound 不区分原因。
	taskID, err := s.assignments.UpdateStatusByNode(ctx, assignmentID, callerNodeID, status, errMsg)
	if err != nil {
		return err
	}

	// PR-S4 task 聚合：失败仅日志，不影响 agent 报进度的成功语义
	if err := s.aggregateTaskStatus(ctx, taskID); err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "scan: aggregate task status failed", err,
				"task_id", taskID, "assignment_id", assignmentID)
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
	if err := s.tasks.UpdateStatus(ctx, taskID, next, finishedAt); err != nil {
		return err
	}
	// PR-S17-OBSV: 进入终态记 metric（CancelTask 直走 UpdateStatus 不经此处，
	// 在 CancelTask 路径单独 inc）
	if next.IsTerminal() {
		s.metrics.TasksTerminal.WithLabelValues(string(next)).Inc()
	}
	return nil
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
			TenantID:     t.TenantID,  // PR-S7 冗余写入便于 ES 过滤
			ProjectID:    t.ProjectID, // PR-S7 冗余写入便于 PA 权限收紧
			TaskID:       t.ID,
			AssignmentID: a.ID,
			NodeID:       a.NodeID,
			Kind:         t.Kind,
			Data:         it.Data,
		})
	}

	// PR-S17-OUTB：开 tx → InsertBulkTx + PublishTx（outbox event）→ commit。
	// PG 提交即"事件已落"承诺；relay 异步消费 → indexer.Index 投 ES。
	// pool=nil（测试 / scaffold）退化到老 InsertBulk 非-TX 路径 + 同步 ES。
	if s.pool == nil {
		return s.reportResultsLegacy(ctx, t, a, rows)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan: begin tx")
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.results.InsertBulkTx(ctx, tx, rows); err != nil {
		return err
	}
	if err := eventbus.PublishTx(ctx, tx, resultsToEvent(rows)); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan: publish outbox event")
	}
	if err := tx.Commit(ctx); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan: commit tx")
	}
	s.metrics.ResultsInserted.Add(float64(len(rows))) // PR-S17-OBSV

	// PR-S8 资产派生：保持 inline 同步（失败仅日志，下次扫描会再追平）。
	// 不放进 outbox：派生视图无幂等问题但出错频率低，且 asset 表 UPSERT 可
	// 自然 catch-up；进 outbox 反增复杂度。
	if s.assets != nil {
		inputs := make([]AssetResultInput, 0, len(rows))
		for _, r := range rows {
			inputs = append(inputs, AssetResultInput{
				TenantID:  r.TenantID,
				ProjectID: r.ProjectID,
				Kind:      string(r.Kind),
				Data:      r.Data,
			})
		}
		if err := s.assets.UpsertFromResults(ctx, inputs); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: derive assets failed", err,
				"task_id", t.ID, "assignment_id", a.ID, "count", len(rows))
		}
	}

	// 即时 ES 写（best-effort，relay 兜底 at-least-once；doc id=ScanResult.ID 幂等）
	if s.indexer != nil {
		if err := s.indexer.Index(ctx, rows); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: index results to ES failed (relay 将兜底重试)", err,
				"task_id", t.ID, "assignment_id", a.ID, "count", len(rows))
		}
	}
	return nil
}

// reportResultsLegacy 是 pool=nil 时（测试 / scaffold）的非-TX 兼容路径。
// 等价于 PR-S6 的原 inline 写法：InsertBulk + sync ES + sync asset。
func (s *service) reportResultsLegacy(
	ctx context.Context,
	t *domain.ScanTask,
	a *domain.TaskAssignment,
	rows []*domain.ScanResult,
) error {
	if err := s.results.InsertBulk(ctx, rows); err != nil {
		return err
	}
	s.metrics.ResultsInserted.Add(float64(len(rows)))
	if s.indexer != nil {
		if err := s.indexer.Index(ctx, rows); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: index results to ES failed", err,
				"task_id", t.ID, "assignment_id", a.ID, "count", len(rows))
		}
	}
	if s.assets != nil {
		inputs := make([]AssetResultInput, 0, len(rows))
		for _, r := range rows {
			inputs = append(inputs, AssetResultInput{
				TenantID:  r.TenantID,
				ProjectID: r.ProjectID,
				Kind:      string(r.Kind),
				Data:      r.Data,
			})
		}
		if err := s.assets.UpsertFromResults(ctx, inputs); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "scan: derive assets failed", err,
				"task_id", t.ID, "assignment_id", a.ID, "count", len(rows))
		}
	}
	return nil
}

// ListResultsByTask（PR-S5）—— 详情页直查。
func (s *service) ListResultsByTask(ctx context.Context, taskID string) ([]*domain.ScanResult, error) {
	if strings.TrimSpace(taskID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "缺 task_id")
	}
	return s.results.ListByTask(ctx, taskID)
}

// SearchResults（PR-S7）—— 全局搜索；走 ES。
//
// 权限：handler 已把 RBAC 注成 ScopedTenantID / ScopedProjectIDs。
// 这里只做：
//  1. PA 路径若 0 个加入项目，直接返空（不打 ES）；
//  2. 用户传的 ProjectID 必须在 ScopedProjectIDs 范围内（防越权穿透）；
//  3. 把 SearchRequest 转 indexer.SearchQuery 调下去。
func (s *service) SearchResults(ctx context.Context, req SearchRequest) (*SearchResultPage, error) {
	if s.indexer == nil {
		return nil, errx.New(errx.ErrUpstreamTimeout,
			"scan: ES 未配置，全局搜索不可用")
	}
	// PA：明确传了空切片表示"加入 0 项目"，直接返空页（不打 ES）
	if req.ScopedProjectIDs != nil && len(req.ScopedProjectIDs) == 0 {
		page, size := indexer.NormalizePage(req.Page, req.PageSize)
		return &SearchResultPage{Items: []*domain.ScanResult{}, Page: page, PageSize: size}, nil
	}
	// 校验用户传的 ProjectID 必在 PA 可见范围内
	if req.ProjectID != "" && req.ScopedProjectIDs != nil {
		ok := false
		for _, p := range req.ScopedProjectIDs {
			if p == req.ProjectID {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errx.New(errx.ErrProjectAccessDenied,
				"无权访问该项目").WithFields("project_id", req.ProjectID)
		}
	}
	q := indexer.SearchQuery{
		Keyword:    req.Keyword,
		TenantID:   req.ScopedTenantID,
		ProjectIDs: req.ScopedProjectIDs,
		ProjectID:  req.ProjectID,
		NodeID:     req.NodeID,
		TaskID:     req.TaskID,
		Kind:       req.Kind,
		TimeFrom:   req.TimeFrom,
		TimeTo:     req.TimeTo,
		Page:       req.Page,
		PageSize:   req.PageSize,
	}
	page, err := s.indexer.Search(ctx, q)
	if err != nil {
		return nil, err
	}
	out := &SearchResultPage{
		Items:    page.Items,
		Total:    page.Total,
		Page:     page.Page,
		PageSize: page.PageSize,
	}
	for _, f := range page.Facets {
		fc := SearchFacet{Field: f.Field, Buckets: make([]SearchFacetBucket, 0, len(f.Buckets))}
		for _, b := range f.Buckets {
			fc.Buckets = append(fc.Buckets, SearchFacetBucket{Key: b.Key, Count: b.Count})
		}
		out.Facets = append(out.Facets, fc)
	}
	return out, nil
}

// TriggerCronTask（PR-S12）—— scheduler 到点回调；从模板派生 immediate 实例。
//
// 模板若已软删 / 取消，则注销 scheduler 后静默返回（避免 cron 反复打日志）。
// 实例 task 的 name 加 [yyyy-MM-dd HH:mm] 后缀以便 UI 区分；
// 走 service.CreateTask 自然触发 dispatch。
func (s *service) TriggerCronTask(ctx context.Context, taskID string) error {
	s.metrics.SchedulerTriggers.Inc() // PR-S17-OBSV：每次回调即计一次
	t, err := s.tasks.GetByID(ctx, taskID)
	if err != nil {
		// 模板已不在（软删 / 不存在）→ 注销 scheduler 防再触发
		if s.scheduler != nil {
			s.scheduler.Remove(taskID)
		}
		return nil //nolint:nilerr // 非异常，cron 自然终止
	}
	if t.ScheduleKind != domain.ScheduleCron {
		// 模板的 schedule_kind 不再是 cron（理论上不会，防御）
		if s.scheduler != nil {
			s.scheduler.Remove(taskID)
		}
		return nil
	}
	if t.Status == domain.TaskCanceled {
		if s.scheduler != nil {
			s.scheduler.Remove(taskID)
		}
		return nil
	}
	req := s.instantiateFromTemplate(t, "[2006-01-02 15:04]")
	if _, err := s.CreateTask(ctx, req); err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "scan: cron trigger CreateTask failed", err,
				"template_task_id", taskID)
		}
		return err
	}
	if s.logger != nil {
		s.logger.Info("scan: cron triggered",
			"template_task_id", taskID, "instance_name", req.Name)
	}
	return nil
}

// instantiateFromTemplate（PR-S18-A）—— 把模板 task 字段复制成新 immediate
// 实例的 CreateTaskRequest。被 TriggerCronTask（cron 触发）+ RetryTask（重试）
// 共用。suffixLayout 是 time.Format 的布局字串：
//   - "[2006-01-02 15:04]"          cron trigger 用
//   - "[retry 2006-01-02 15:04]"   RetryTask 用
//
// 自动截断 name 不超 TaskNameMaxLen；SourceTaskID 指模板 ID。
func (s *service) instantiateFromTemplate(t *domain.ScanTask, suffixLayout string) CreateTaskRequest {
	name := t.Name + " " + s.now().UTC().Format(suffixLayout)
	if len(name) > domain.TaskNameMaxLen {
		name = name[:domain.TaskNameMaxLen]
	}
	srcID := t.ID
	return CreateTaskRequest{
		TenantID:     t.TenantID,
		ProjectID:    t.ProjectID,
		Name:         name,
		Kind:         t.Kind,
		Target:       t.Target,
		Targets:      append([]string(nil), t.Targets...), // PR-S22：保留批量目标
		TargetKind:   t.TargetKind,
		ScheduleKind: domain.ScheduleImmediate,
		Settings:     t.Settings,
		CreatedBy:    t.CreatedBy,
		SourceTaskID: &srcID,
	}
}

// SweepStaleAssignments（PR-S14）—— 把卡 pulled/running > timeout 的派发
// 标 failed，并触发涉及 task 的状态聚合。
//
// 失败处理：单条 UpdateStatus 失败仅日志，继续扫其他；最终返成功标 failed 的数量。
// caller 一般是 sweeper goroutine，每 N 秒调一次。
func (s *service) SweepStaleAssignments(ctx context.Context, timeout time.Duration) (int, error) {
	if timeout <= 0 {
		return 0, errx.New(errx.ErrInvalidInput, "sweep: timeout 必须 > 0")
	}
	cutoff := s.now().Add(-timeout)
	stale, err := s.assignments.ListStaleRunning(ctx, cutoff)
	if err != nil {
		return 0, err
	}
	if len(stale) == 0 {
		return 0, nil
	}
	swept := 0
	touchedTasks := make(map[string]struct{}, len(stale))
	for _, a := range stale {
		errMsg := "assignment timeout (no progress for > " + timeout.String() + ")"
		if err := s.assignments.UpdateStatus(ctx, a.ID, domain.AssignmentFailed, errMsg); err != nil {
			if s.logger != nil {
				s.logger.LogError(ctx, "sweep: mark assignment failed", err,
					"assignment_id", a.ID, "task_id", a.TaskID)
			}
			continue
		}
		swept++
		s.metrics.SweeperSwept.Inc() // PR-S17-OBSV：每标 failed 一条 +1
		touchedTasks[a.TaskID] = struct{}{}
	}
	for tID := range touchedTasks {
		if err := s.aggregateTaskStatus(ctx, tID); err != nil && s.logger != nil {
			s.logger.LogError(ctx, "sweep: aggregate after sweep", err, "task_id", tID)
		}
	}
	if s.logger != nil && swept > 0 {
		s.logger.Info("scan: sweep stale assignments",
			"swept", swept, "tasks_touched", len(touchedTasks))
	}
	return swept, nil
}

// RetryTask（PR-S14）—— 把 failed/canceled task 作模板复制成 immediate 实例。
//
// 与 TriggerCronTask 的复制语义相同，差别：
//   - 校原 task 状态必须 ∈ {failed, canceled}
//   - name 加 "[retry yyyy-MM-dd HH:mm]" 后缀以便 UI 区分
func (s *service) RetryTask(ctx context.Context, taskID string) (*domain.ScanTask, error) {
	t, err := s.tasks.GetByID(ctx, taskID)
	if err != nil {
		return nil, err
	}
	if t.Status != domain.TaskFailed && t.Status != domain.TaskCanceled {
		return nil, errx.New(errx.ErrTaskInvalidState,
			"仅 failed / canceled 可重试").
			WithFields("status", string(t.Status))
	}
	return s.CreateTask(ctx, s.instantiateFromTemplate(t, "[retry 2006-01-02 15:04]"))
}

// GetArtifactDownloadURL（PR-S16）—— 签预签名 GET URL。
//
// 安全：MVP 不解析 key 中的 tenant 前缀做强校验，依赖 RBAC handler 层
// + MinIO bucket scope 已隔离 tenant 数据。后续可加 key 前缀 vs principal.TenantID
// 反查校。
func (s *service) GetArtifactDownloadURL(
	ctx context.Context,
	key string,
) (string, time.Time, error) {
	if s.artifacts == nil {
		return "", time.Time{}, errx.New(errx.ErrUpstreamTimeout,
			"scan: artifact store 未配置")
	}
	// PR-S18-A: 复用 artifact.ValidateKey，删本地副本
	if err := artifact.ValidateKey(key); err != nil {
		return "", time.Time{}, err
	}
	const ttl = 10 * time.Minute
	url, err := s.artifacts.PresignGetURL(ctx, key, ttl)
	if err != nil {
		return "", time.Time{}, err
	}
	return url, s.now().Add(ttl), nil
}
