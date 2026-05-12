// PR-S23 扫描套件 service 实现。把套件 + targets[] 展开成 N immediate task。
package scan

import (
	"context"
	"strings"
	"time"

	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan/repo"
)

// CreateSuiteRequest 创建套件入参。
type CreateSuiteRequest struct {
	TenantID        string  // 必填（handler 从 principal 注）
	ProjectID       *string // nil = 跨项目；非空 = 限本项目
	Name            string
	Kinds           []domain.TaskKind
	TargetKind      domain.TargetKind
	DefaultSettings map[string]any
	CreatedBy       string
}

// ListSuitesRequest 列套件入参。
type ListSuitesRequest struct {
	TenantID  string
	ProjectID string // 非空 = 含跨项目套件 + 该项目套件
	Keyword   string
	Page      int
	PageSize  int
}

// ListSuitesResult 分页返回。
type ListSuitesResult struct {
	Suites   []*domain.ScanSuite
	Total    int
	Page     int
	PageSize int
}

// RunSuiteRequest 触发一次 RunSuite 入参。
type RunSuiteRequest struct {
	SuiteID   string
	ProjectID string   // run 必须落在某个具体项目（套件可跨项目，run 不可）
	Targets   []string // 必填，至少 1
	CreatedBy string
}

// SuiteRunDetail GetSuiteRun 返回 run + 子 tasks。
type SuiteRunDetail struct {
	Run   *domain.ScanSuiteRun
	Suite *domain.ScanSuite
	Tasks []*domain.ScanTask
}

// ListSuiteRunsRequest 列 run 入参。
type ListSuiteRunsRequest struct {
	TenantID  string
	ProjectID string
	SuiteID   string
	Page      int
	PageSize  int
}

// ListSuiteRunsResult 分页返回。
type ListSuiteRunsResult struct {
	Runs     []*domain.ScanSuiteRun
	Total    int
	Page     int
	PageSize int
}

// CreateSuite 创建套件模板。
//
// project_id 非空时校项目存在 + 同租户 + 未归档。
// project_id nil 时仅校 tenant 存在（handler 已注 tenant_id）。
func (s *service) CreateSuite(ctx context.Context, req CreateSuiteRequest) (*domain.ScanSuite, error) {
	if s.suites == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	if req.ProjectID != nil && strings.TrimSpace(*req.ProjectID) != "" {
		p, err := s.projects.GetByID(ctx, *req.ProjectID)
		if err != nil {
			return nil, err
		}
		if p.TenantID != req.TenantID {
			return nil, errx.New(errx.ErrProjectAccessDenied, "project 不属于此租户")
		}
		if p.Status == tenancydomain.ProjectArchived {
			return nil, errx.New(errx.ErrProjectArchived, "归档项目不能创建套件")
		}
	}
	suite := &domain.ScanSuite{
		TenantID:        req.TenantID,
		ProjectID:       req.ProjectID,
		Name:            req.Name,
		Kinds:           req.Kinds,
		TargetKind:      req.TargetKind,
		DefaultSettings: req.DefaultSettings,
		CreatedBy:       req.CreatedBy,
	}
	if err := s.suites.Insert(ctx, suite); err != nil {
		return nil, err
	}
	return suite, nil
}

// ListSuites 列套件（同租户内可见的：跨项目 + 该项目）。
func (s *service) ListSuites(ctx context.Context, req ListSuitesRequest) (*ListSuitesResult, error) {
	if s.suites == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	suites, total, err := s.suites.List(ctx, repo.SuiteFilter{
		TenantID:  req.TenantID,
		ProjectID: req.ProjectID,
		Keyword:   req.Keyword,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListSuitesResult{
		Suites: suites, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

// GetSuite 取单个套件（已软删返 NotFound）。
func (s *service) GetSuite(ctx context.Context, id string) (*domain.ScanSuite, error) {
	if s.suites == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	return s.suites.GetByID(ctx, id)
}

// DeleteSuite 软删；不影响已 RunSuite 生成的 task/run。
func (s *service) DeleteSuite(ctx context.Context, id string) error {
	if s.suites == nil {
		return errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	return s.suites.SoftDelete(ctx, id)
}

// RunSuite 用套件 + targets[] 触发一次扫描：每 kind 1 个 immediate task。
//
// 流程：
//  1. 取套件 + 校 project（套件 project_id 非空时必须匹配；空时允许任何项目）
//  2. INSERT scan_suite_runs row
//  3. for each kind in suite.Kinds：调 CreateTask(kind=K, targets=targets, suite_run_id=run.id)
//  4. 任何一个 CreateTask 失败 → 中断 + 把 run 标 failed（不回滚已建 task，记 partial）
//  5. 返 run（caller 自行 ListTasks(suite_run_id=...) 查关联子 task）
func (s *service) RunSuite(ctx context.Context, req RunSuiteRequest) (*domain.ScanSuiteRun, error) {
	if s.suites == nil || s.suiteRuns == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	if strings.TrimSpace(req.SuiteID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "suite_id 不能为空")
	}
	if strings.TrimSpace(req.ProjectID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	// PR-S24：先展开 CIDR/范围，再去重。展开上限 4096。
	expanded, err := domain.ExpandTargets(req.Targets, domain.DefaultMaxExpansion)
	if err != nil {
		return nil, err
	}
	targets := dedupTargets(expanded)
	if len(targets) == 0 {
		return nil, errx.New(errx.ErrTaskNoTargets, "targets 至少 1 个")
	}

	suite, err := s.suites.GetByID(ctx, req.SuiteID)
	if err != nil {
		return nil, err
	}
	if suite.ProjectID != nil && *suite.ProjectID != req.ProjectID {
		return nil, errx.New(errx.ErrProjectAccessDenied,
			"该套件仅限指定项目使用").
			WithFields("suite_project", *suite.ProjectID, "req_project", req.ProjectID)
	}

	// 校 project 存在 + 同租户 + 未归档
	p, err := s.projects.GetByID(ctx, req.ProjectID)
	if err != nil {
		return nil, err
	}
	if p.TenantID != suite.TenantID {
		return nil, errx.New(errx.ErrProjectAccessDenied, "project 不属于套件所在租户")
	}
	if p.Status == tenancydomain.ProjectArchived {
		return nil, errx.New(errx.ErrProjectArchived, "归档项目不能 RunSuite")
	}

	run := &domain.ScanSuiteRun{
		SuiteID:   suite.ID,
		TenantID:  suite.TenantID,
		ProjectID: req.ProjectID,
		Targets:   targets,
		Status:    domain.SuiteRunPending,
		CreatedBy: req.CreatedBy,
	}
	if err := s.suiteRuns.Insert(ctx, run); err != nil {
		return nil, err
	}

	if len(suite.Kinds) == 0 {
		_ = s.suiteRuns.UpdateStatus(ctx, run.ID, domain.SuiteRunFailed, true)
		run.Status = domain.SuiteRunFailed
		return run, errx.New(errx.ErrInternal, "suite 无 kinds 可触发")
	}

	// PR-S27 chaining：只创建第 1 个 step 的 task。
	// 后续 step 由 aggregateSuiteRunStatus 在前一 step 完成时 + extractor 自动创建。
	if err := s.createStepTask(ctx, suite, run, 0, targets, req.CreatedBy); err != nil {
		_ = s.suiteRuns.UpdateStatus(ctx, run.ID, domain.SuiteRunFailed, true)
		run.Status = domain.SuiteRunFailed
		return run, err
	}
	return run, nil
}

// createStepTask 创建 suite.Kinds[step] 对应的 task（共享 targets[]）。
// step 在 [0, len(suite.Kinds)) 范围内；调用方保证。
func (s *service) createStepTask(
	ctx context.Context,
	suite *domain.ScanSuite,
	run *domain.ScanSuiteRun,
	step int,
	targets []string,
	createdBy string,
) error {
	kind := suite.Kinds[step]
	runID := run.ID
	taskSettings := map[string]any{}
	if v, ok := suite.DefaultSettings[string(kind)]; ok {
		if m, ok := v.(map[string]any); ok {
			taskSettings = m
		}
	}
	now := s.now()
	taskName := suite.Name + " · " + string(kind) +
		" " + now.UTC().Format("[2006-01-02 15:04]")
	if len(taskName) > domain.TaskNameMaxLen {
		taskName = taskName[:domain.TaskNameMaxLen]
	}
	if len(targets) == 0 {
		return errx.New(errx.ErrTaskNoTargets, "chain step 无 targets")
	}
	_, err := s.CreateTask(ctx, CreateTaskRequest{
		TenantID:     suite.TenantID,
		ProjectID:    run.ProjectID,
		Name:         taskName,
		Kind:         kind,
		Target:       targets[0],
		Targets:      targets,
		TargetKind:   suite.TargetKind,
		ScheduleKind: domain.ScheduleImmediate,
		Settings:     taskSettings,
		CreatedBy:    createdBy,
		SuiteRunID:   &runID,
	})
	if err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "scan: suite run CreateTask failed", err,
				"suite_id", suite.ID, "run_id", run.ID, "step", step, "kind", string(kind))
		}
		return err
	}
	return nil
}

// GetSuiteRun 返 run + suite + 关联子 tasks（详情页用）。
func (s *service) GetSuiteRun(ctx context.Context, id string) (*SuiteRunDetail, error) {
	if s.suites == nil || s.suiteRuns == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	run, err := s.suiteRuns.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	suite, err := s.suites.GetByID(ctx, run.SuiteID)
	if err != nil {
		// 套件被删 → 仍返 run（suite 留 nil）；前端兼容
		suite = nil
	}
	tasks, _, err := s.tasks.List(ctx, repo.TaskFilter{
		TenantID:   run.TenantID,
		SuiteRunID: id,
	}, repo.Page{Page: 1, PageSize: 200})
	if err != nil {
		return nil, err
	}
	return &SuiteRunDetail{Run: run, Suite: suite, Tasks: tasks}, nil
}

// ListSuiteRuns 透传 repo。
func (s *service) ListSuiteRuns(ctx context.Context, req ListSuiteRunsRequest) (*ListSuiteRunsResult, error) {
	if s.suiteRuns == nil {
		return nil, errx.New(errx.ErrNotImplemented, "scan: suite repo 未配置")
	}
	runs, total, err := s.suiteRuns.List(ctx, repo.SuiteRunFilter{
		TenantID:  req.TenantID,
		ProjectID: req.ProjectID,
		SuiteID:   req.SuiteID,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListSuiteRunsResult{
		Runs: runs, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

// aggregateSuiteRunStatus 根据当前 step 的子 task 状态推进 run.status / chaining。
//
// PR-S27 chaining 模型：
//   - run.CurrentStep 指向 suite.Kinds[] 当前正在跑的索引
//   - 只看当前 step 的 task（按 kind 过滤），不混计早先 step
//   - 当前 step 全部 terminal：
//   - 含 failed/canceled → run.failed（链终止）
//   - 全 completed →
//     · 若是最后一步 → run.completed
//     · 否则 → extractor 取下一 step targets → 创建下一 step task；空 targets → run.completed（链断）
//   - 否则（still pending/running）→ run.running / pending
func (s *service) aggregateSuiteRunStatus(ctx context.Context, runID string) error {
	if s.suiteRuns == nil {
		return nil
	}
	run, err := s.suiteRuns.GetByID(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status.IsTerminal() {
		return nil
	}
	suite, err := s.suites.GetByID(ctx, run.SuiteID)
	if err != nil {
		// 套件被删 → 降级走老逻辑（按全 tasks 聚合）
		return s.aggregateSuiteRunStatusLegacy(ctx, run)
	}
	if run.CurrentStep < 0 || run.CurrentStep >= len(suite.Kinds) {
		// 索引越界（旧数据 / 异常）→ 走老逻辑
		return s.aggregateSuiteRunStatusLegacy(ctx, run)
	}

	currentKind := suite.Kinds[run.CurrentStep]
	tasks, _, err := s.tasks.List(ctx, repo.TaskFilter{
		TenantID:   run.TenantID,
		SuiteRunID: runID,
		Kind:       currentKind,
	}, repo.Page{Page: 1, PageSize: 200})
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		// 当前 step 还没建 task（极少）
		return nil
	}

	allTerminal, anyRunning := true, false
	completed, failed, canceled := 0, 0, 0
	for _, t := range tasks {
		switch t.Status {
		case domain.TaskPending:
			allTerminal = false
		case domain.TaskRunning:
			allTerminal = false
			anyRunning = true
		case domain.TaskCompleted:
			completed++
		case domain.TaskFailed:
			failed++
		case domain.TaskCanceled:
			canceled++
		}
	}

	// 未全 terminal：仍在跑当前 step
	if !allTerminal {
		next := domain.SuiteRunPending
		if anyRunning {
			next = domain.SuiteRunRunning
		}
		if next != run.Status {
			return s.suiteRuns.UpdateStatus(ctx, runID, next, false)
		}
		return nil
	}

	// 当前 step 全 terminal — 判定推进 / 终止 / 链断
	if failed > 0 || canceled > 0 {
		// 链终止
		nextStatus := domain.SuiteRunFailed
		if canceled == len(tasks) {
			nextStatus = domain.SuiteRunCanceled
		} else if completed > 0 {
			nextStatus = domain.SuiteRunPartialFailed
		}
		return s.suiteRuns.UpdateStatus(ctx, runID, nextStatus, true)
	}

	// 全 completed：考虑推进下一步
	if run.CurrentStep+1 >= len(suite.Kinds) {
		// 最后一步 → 完成
		return s.suiteRuns.UpdateStatus(ctx, runID, domain.SuiteRunCompleted, true)
	}

	// 取下一 step 输入：当前 step 所有 task 的 results → extractor
	nextTargets, err := s.extractNextStepTargets(ctx, tasks, currentKind)
	if err != nil {
		return err
	}
	if len(nextTargets) == 0 {
		// 链断：当前 step 成功但没产物（无 live URL / 无子域名）→ 整链 completed
		if s.logger != nil {
			s.logger.Info("scan: suite chain ends early (no output)",
				"run_id", runID, "step", run.CurrentStep, "kind", string(currentKind))
		}
		return s.suiteRuns.UpdateStatus(ctx, runID, domain.SuiteRunCompleted, true)
	}

	nextStep := run.CurrentStep + 1
	if err := s.createStepTask(ctx, suite, run, nextStep, nextTargets, run.CreatedBy); err != nil {
		_ = s.suiteRuns.UpdateStatus(ctx, runID, domain.SuiteRunFailed, true)
		return err
	}
	// 推进 step + 状态保 running
	if err := s.suiteRuns.UpdateCurrentStep(ctx, runID, nextStep); err != nil {
		return err
	}
	if run.Status != domain.SuiteRunRunning {
		return s.suiteRuns.UpdateStatus(ctx, runID, domain.SuiteRunRunning, false)
	}
	return nil
}

// extractNextStepTargets 当前 step 全 completed → 拉所有 result → 走 extractor。
func (s *service) extractNextStepTargets(
	ctx context.Context,
	currentTasks []*domain.ScanTask,
	currentKind domain.TaskKind,
) ([]string, error) {
	allResults := []domain.ResultData{}
	for _, t := range currentTasks {
		rows, err := s.results.ListByTask(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if r.Data != nil {
				allResults = append(allResults, r.Data)
			}
		}
	}
	return domain.ExtractTargetsForKind(currentKind, allResults), nil
}

// aggregateSuiteRunStatusLegacy 老逻辑：套件被删 / 索引越界时降级用。
func (s *service) aggregateSuiteRunStatusLegacy(ctx context.Context, run *domain.ScanSuiteRun) error {
	tasks, _, err := s.tasks.List(ctx, repo.TaskFilter{
		TenantID:   run.TenantID,
		SuiteRunID: run.ID,
	}, repo.Page{Page: 1, PageSize: 200})
	if err != nil {
		return err
	}
	if len(tasks) == 0 {
		return nil
	}
	allTerminal, anyRunning := true, false
	completed, failed, canceled := 0, 0, 0
	for _, t := range tasks {
		switch t.Status {
		case domain.TaskPending:
			allTerminal = false
		case domain.TaskRunning:
			allTerminal = false
			anyRunning = true
		case domain.TaskCompleted:
			completed++
		case domain.TaskFailed:
			failed++
		case domain.TaskCanceled:
			canceled++
		}
	}
	var next domain.SuiteRunStatus
	switch {
	case anyRunning:
		next = domain.SuiteRunRunning
	case !allTerminal:
		next = domain.SuiteRunPending
	case completed > 0 && failed == 0 && canceled == 0:
		next = domain.SuiteRunCompleted
	case failed > 0 && completed == 0:
		next = domain.SuiteRunFailed
	case canceled == len(tasks):
		next = domain.SuiteRunCanceled
	default:
		next = domain.SuiteRunPartialFailed
	}
	if next == run.Status {
		return nil
	}
	return s.suiteRuns.UpdateStatus(ctx, run.ID, next, next.IsTerminal())
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pageSizeOrDefault(ps, def int) int {
	if ps <= 0 {
		return def
	}
	return ps
}

// 防 unused import 警告
var _ = time.Now
