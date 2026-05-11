// service_test.go: scan.service 单测（PR-S17-TEST）。
//
// 覆盖目标（service.go 中期评审 P0-9）：
//   - ReportResults：参数校验 / GetByID 错 / 节点伪造 / 正常 legacy 路径
//   - TriggerCronTask：模板缺失 / 非 cron / canceled → 静默 + scheduler.Remove；
//     正常 → CreateTask 调一次 + name 后缀 + SourceTaskID 指模板
//   - RetryTask：pending / running 拒；failed / canceled 通过 + name 后缀
//   - SweepStaleAssignments：timeout=0 / 0 stale / 多 stale 全部 failed + 聚合
//   - aggregateTaskStatus：canceled 不动 / 0 assignments / running / failed /
//     completed + TasksTerminal metric Inc
//
// 设计要点：
//   - pool=nil 让 ReportResults 走 reportResultsLegacy（避免起真 PG）
//   - indexer / assets / scheduler / artifacts 全 nil，对应 nil-check 路径自然跳过
//   - service.now 替换为固定时间，使 name 后缀可断言
//   - metricsscan.Noop() 注入；CounterVec.WithLabelValues + testutil.ToFloat64 校 Inc
package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan/metricsscan"
	"github.com/ffff5sec/RedMatrix/internal/scan/repo"
	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// === stub TaskRepository =====================================================

type stubTaskRepo struct {
	tasks map[string]*domain.ScanTask

	insertErr  error
	getErr     error
	updateErr  error
	listErr    error
	deleteErr  error
	cronErr    error
	templates  []repo.CronTemplateRow
	insertCall int
	updateCall int
	statusLog  []taskStatusUpdate
}

type taskStatusUpdate struct {
	ID         string
	Status     domain.TaskStatus
	FinishedAt *string
}

func newStubTaskRepo() *stubTaskRepo {
	return &stubTaskRepo{tasks: map[string]*domain.ScanTask{}}
}

func (r *stubTaskRepo) put(t *domain.ScanTask) {
	if t.ID == "" {
		t.ID = "tk-" + t.Name
	}
	cp := *t
	r.tasks[t.ID] = &cp
}

func (r *stubTaskRepo) Insert(_ context.Context, t *domain.ScanTask) error {
	r.insertCall++
	if r.insertErr != nil {
		return r.insertErr
	}
	if t.ID == "" {
		// 与 PG 一致：模拟生成 UUID
		t.ID = "auto-" + t.Name
	}
	cp := *t
	r.tasks[t.ID] = &cp
	return nil
}

func (r *stubTaskRepo) GetByID(_ context.Context, id string) (*domain.ScanTask, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	t, ok := r.tasks[id]
	if !ok {
		return nil, errx.New(errx.ErrTaskNotFound, "task not found").WithFields("id", id)
	}
	cp := *t
	return &cp, nil
}

func (r *stubTaskRepo) List(_ context.Context, _ repo.TaskFilter, _ repo.Page) ([]*domain.ScanTask, int, error) {
	if r.listErr != nil {
		return nil, 0, r.listErr
	}
	out := make([]*domain.ScanTask, 0, len(r.tasks))
	for _, t := range r.tasks {
		cp := *t
		out = append(out, &cp)
	}
	return out, len(out), nil
}

func (r *stubTaskRepo) UpdateStatus(_ context.Context, id string, status domain.TaskStatus, finishedAt *string) error {
	r.updateCall++
	r.statusLog = append(r.statusLog, taskStatusUpdate{ID: id, Status: status, FinishedAt: finishedAt})
	if r.updateErr != nil {
		return r.updateErr
	}
	t, ok := r.tasks[id]
	if !ok {
		return errx.New(errx.ErrTaskNotFound, "task not found")
	}
	t.Status = status
	return nil
}

func (r *stubTaskRepo) SoftDelete(_ context.Context, id string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	t, ok := r.tasks[id]
	if !ok {
		return errx.New(errx.ErrTaskNotFound, "task not found")
	}
	now := time.Now().UTC()
	t.DeletedAt = &now
	return nil
}

func (r *stubTaskRepo) ListCronTemplates(_ context.Context) ([]repo.CronTemplateRow, error) {
	if r.cronErr != nil {
		return nil, r.cronErr
	}
	return r.templates, nil
}

// === stub AssignmentRepository ===============================================

type stubAssignmentRepo struct {
	rows map[string]*domain.TaskAssignment

	insertBulkErr      error
	listByTaskErr      error
	countErr           error
	pullErr            error
	getErr             error
	updateStatusErr    error
	listStaleErr       error
	updateByNodeErr    error
	updateByNodeTaskID string

	insertBulkCalls [][]*domain.TaskAssignment
	listByTaskCalls []string
	updateStatusLog []assignmentStatusUpdate
	staleList       []*domain.TaskAssignment
}

type assignmentStatusUpdate struct {
	ID     string
	Status domain.AssignmentStatus
	ErrMsg string
}

func newStubAssignmentRepo() *stubAssignmentRepo {
	return &stubAssignmentRepo{rows: map[string]*domain.TaskAssignment{}}
}

func (r *stubAssignmentRepo) put(a *domain.TaskAssignment) {
	if a.ID == "" {
		a.ID = "as-" + a.TaskID + "-" + a.NodeID
	}
	cp := *a
	r.rows[a.ID] = &cp
}

func (r *stubAssignmentRepo) InsertBulk(_ context.Context, assignments []*domain.TaskAssignment) error {
	r.insertBulkCalls = append(r.insertBulkCalls, assignments)
	if r.insertBulkErr != nil {
		return r.insertBulkErr
	}
	for _, a := range assignments {
		r.put(a)
	}
	return nil
}

func (r *stubAssignmentRepo) ListByTask(_ context.Context, taskID string) ([]*domain.TaskAssignment, error) {
	r.listByTaskCalls = append(r.listByTaskCalls, taskID)
	if r.listByTaskErr != nil {
		return nil, r.listByTaskErr
	}
	out := make([]*domain.TaskAssignment, 0, len(r.rows))
	for _, a := range r.rows {
		if a.TaskID == taskID {
			cp := *a
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *stubAssignmentRepo) CountByTaskIDs(_ context.Context, taskIDs []string) (map[string]int, error) {
	if r.countErr != nil {
		return nil, r.countErr
	}
	counts := map[string]int{}
	for _, id := range taskIDs {
		for _, a := range r.rows {
			if a.TaskID == id {
				counts[id]++
			}
		}
	}
	return counts, nil
}

func (r *stubAssignmentRepo) PullForNode(_ context.Context, nodeID string) ([]*domain.TaskAssignment, error) {
	if r.pullErr != nil {
		return nil, r.pullErr
	}
	out := make([]*domain.TaskAssignment, 0)
	for _, a := range r.rows {
		if a.NodeID == nodeID && a.Status == domain.AssignmentAssigned {
			a.Status = domain.AssignmentPulled
			cp := *a
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *stubAssignmentRepo) GetByID(_ context.Context, id string) (*domain.TaskAssignment, error) {
	if r.getErr != nil {
		return nil, r.getErr
	}
	a, ok := r.rows[id]
	if !ok {
		return nil, errx.New(errx.ErrTaskNotFound, "assignment not found").WithFields("id", id)
	}
	cp := *a
	return &cp, nil
}

func (r *stubAssignmentRepo) UpdateStatus(_ context.Context, id string, status domain.AssignmentStatus, errMsg string) error {
	r.updateStatusLog = append(r.updateStatusLog, assignmentStatusUpdate{ID: id, Status: status, ErrMsg: errMsg})
	if r.updateStatusErr != nil {
		return r.updateStatusErr
	}
	a, ok := r.rows[id]
	if !ok {
		return errx.New(errx.ErrTaskNotFound, "assignment not found")
	}
	a.Status = status
	a.Error = errMsg
	return nil
}

func (r *stubAssignmentRepo) ListStaleRunning(_ context.Context, _ time.Time) ([]*domain.TaskAssignment, error) {
	if r.listStaleErr != nil {
		return nil, r.listStaleErr
	}
	return r.staleList, nil
}

func (r *stubAssignmentRepo) UpdateStatusByNode(_ context.Context, id, nodeID string, status domain.AssignmentStatus, errMsg string) (string, error) {
	if r.updateByNodeErr != nil {
		return "", r.updateByNodeErr
	}
	a, ok := r.rows[id]
	if !ok || a.NodeID != nodeID {
		return "", errx.New(errx.ErrTaskNotFound, "assignment not found")
	}
	a.Status = status
	a.Error = errMsg
	if r.updateByNodeTaskID != "" {
		return r.updateByNodeTaskID, nil
	}
	return a.TaskID, nil
}

// === stub ResultRepository ===================================================

type stubResultRepo struct {
	insertBulkErr   error
	insertBulkTxErr error
	listErr         error
	countErr        error
	rows            []*domain.ScanResult
	insertBulkCalls [][]*domain.ScanResult
}

func newStubResultRepo() *stubResultRepo {
	return &stubResultRepo{rows: nil}
}

func (r *stubResultRepo) InsertBulk(_ context.Context, items []*domain.ScanResult) error {
	r.insertBulkCalls = append(r.insertBulkCalls, items)
	if r.insertBulkErr != nil {
		return r.insertBulkErr
	}
	r.rows = append(r.rows, items...)
	return nil
}

func (r *stubResultRepo) InsertBulkTx(_ context.Context, _ pgx.Tx, items []*domain.ScanResult) error {
	if r.insertBulkTxErr != nil {
		return r.insertBulkTxErr
	}
	r.rows = append(r.rows, items...)
	return nil
}

func (r *stubResultRepo) ListByTask(_ context.Context, taskID string) ([]*domain.ScanResult, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := make([]*domain.ScanResult, 0, len(r.rows))
	for _, x := range r.rows {
		if x.TaskID == taskID {
			out = append(out, x)
		}
	}
	return out, nil
}

func (r *stubResultRepo) CountByTaskIDs(_ context.Context, taskIDs []string) (map[string]int, error) {
	if r.countErr != nil {
		return nil, r.countErr
	}
	counts := map[string]int{}
	for _, id := range taskIDs {
		for _, x := range r.rows {
			if x.TaskID == id {
				counts[id]++
			}
		}
	}
	return counts, nil
}

// === stub ProjectLookup / NodeLister / AllowedNodesLookup ====================

type stubProjectLookup struct {
	projects map[string]*tenancydomain.Project
	err      error
}

func newStubProjectLookup() *stubProjectLookup {
	return &stubProjectLookup{projects: map[string]*tenancydomain.Project{}}
}

func (s *stubProjectLookup) put(p *tenancydomain.Project) { s.projects[p.ID] = p }

func (s *stubProjectLookup) GetByID(_ context.Context, id string) (*tenancydomain.Project, error) {
	if s.err != nil {
		return nil, s.err
	}
	p, ok := s.projects[id]
	if !ok {
		return nil, errx.New(errx.ErrProjectNotFound, "project not found")
	}
	cp := *p
	return &cp, nil
}

type stubNodeLister struct {
	nodes []*tenancydomain.Node
	err   error
}

func (s *stubNodeLister) List(_ context.Context, _ tenancyrepo.NodeFilter, _ tenancyrepo.Page) ([]*tenancydomain.Node, int, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	return s.nodes, len(s.nodes), nil
}

type stubAllowedNodesLookup struct {
	rows map[string]tenancydomain.AllowedNodes
	err  error
}

func newStubAllowedNodesLookup() *stubAllowedNodesLookup {
	return &stubAllowedNodesLookup{rows: map[string]tenancydomain.AllowedNodes{}}
}

func (s *stubAllowedNodesLookup) Get(_ context.Context, projectID string) (tenancydomain.AllowedNodes, error) {
	if s.err != nil {
		return tenancydomain.AllowedNodes{}, s.err
	}
	if v, ok := s.rows[projectID]; ok {
		return v, nil
	}
	// 默认全开
	return tenancydomain.AllowedNodes{AllNodes: true}, nil
}

// === stub Scheduler ==========================================================

type stubScheduler struct {
	added   []struct{ ID, Expr string }
	removed []string
	addErr  error
}

func (s *stubScheduler) Add(taskID, expr string) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.added = append(s.added, struct{ ID, Expr string }{taskID, expr})
	return nil
}

func (s *stubScheduler) Remove(taskID string) {
	s.removed = append(s.removed, taskID)
}

// === fixture =================================================================

// fixedTime 给 service.now 用，使 name suffix 可断言。
func fixedTime() time.Time {
	return time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC)
}

// testHarness 打包所有 stub + 暴露未导出的 service（同包测可直拿 *service）。
type testHarness struct {
	tasks       *stubTaskRepo
	assignments *stubAssignmentRepo
	results     *stubResultRepo
	projects    *stubProjectLookup
	nodes       *stubNodeLister
	allowed     *stubAllowedNodesLookup
	scheduler   *stubScheduler
	svc         *service
	metrics     *metricsscan.Collectors
}

func newHarness(t *testing.T) *testHarness {
	t.Helper()
	h := &testHarness{
		tasks:       newStubTaskRepo(),
		assignments: newStubAssignmentRepo(),
		results:     newStubResultRepo(),
		projects:    newStubProjectLookup(),
		nodes:       &stubNodeLister{},
		allowed:     newStubAllowedNodesLookup(),
		scheduler:   &stubScheduler{},
		metrics:     metricsscan.Noop(),
	}
	svc, err := NewService(
		h.tasks, h.assignments, h.results,
		h.projects, h.nodes, h.allowed,
		nil, // pool=nil → ReportResults 走 legacy
		nil, // indexer
		nil, // assets
		h.scheduler,
		nil, // artifacts
		h.metrics,
		nil, // logger
	)
	require.NoError(t, err)
	s := svc.(*service)
	s.now = fixedTime
	h.svc = s
	return h
}

// === Tests: ReportResults ====================================================

func TestReportResults_EmptyCallerNodeID(t *testing.T) {
	h := newHarness(t)
	err := h.svc.ReportResults(context.Background(), "", "as-1", []ResultItem{{Data: map[string]any{"x": 1}}})
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestReportResults_EmptyAssignmentID(t *testing.T) {
	h := newHarness(t)
	err := h.svc.ReportResults(context.Background(), "node-1", "", []ResultItem{{Data: map[string]any{"x": 1}}})
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestReportResults_EmptyItems_NoOp(t *testing.T) {
	h := newHarness(t)
	// 即便 assignment 不存在也不去查（短路）
	err := h.svc.ReportResults(context.Background(), "node-1", "as-1", nil)
	assert.NoError(t, err)
	assert.Empty(t, h.results.insertBulkCalls)
}

func TestReportResults_AssignmentNotFound(t *testing.T) {
	h := newHarness(t)
	err := h.svc.ReportResults(context.Background(), "node-1", "missing", []ResultItem{{Data: map[string]any{}}})
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrTaskNotFound, code)
}

func TestReportResults_NodeMismatch_Forbidden(t *testing.T) {
	h := newHarness(t)
	// 注 task + assignment：assignment 属 node-A，caller 是 node-B → 拒
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "1.2.3.4", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{
		ID: "as-1", TaskID: "tk-1", NodeID: "node-A", Status: domain.AssignmentRunning,
	})
	err := h.svc.ReportResults(context.Background(), "node-B", "as-1",
		[]ResultItem{{Data: map[string]any{"port": 22}}})
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrTaskNotFound, code, "防伪造统一返 TaskNotFound 不泄露存在性")
	assert.Empty(t, h.results.insertBulkCalls)
}

func TestReportResults_Legacy_HappyPath(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "1.2.3.4", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{
		ID: "as-1", TaskID: "tk-1", NodeID: "node-1", Status: domain.AssignmentRunning,
	})
	items := []ResultItem{
		{Data: map[string]any{"port": 22, "service": "ssh"}},
		{Data: map[string]any{"port": 80, "service": "http"}},
	}
	err := h.svc.ReportResults(context.Background(), "node-1", "as-1", items)
	require.NoError(t, err)
	require.Len(t, h.results.insertBulkCalls, 1)
	rows := h.results.insertBulkCalls[0]
	require.Len(t, rows, 2)
	for i, r := range rows {
		assert.Equal(t, "ten-1", r.TenantID, "row %d: tenant", i)
		assert.Equal(t, "p-1", r.ProjectID, "row %d: project", i)
		assert.Equal(t, "tk-1", r.TaskID, "row %d: task", i)
		assert.Equal(t, "as-1", r.AssignmentID, "row %d: assignment", i)
		assert.Equal(t, "node-1", r.NodeID, "row %d: node", i)
		assert.Equal(t, domain.KindPortScan, r.Kind, "row %d: kind", i)
		assert.Equal(t, items[i].Data, r.Data, "row %d: data", i)
	}
}

// === Tests: TriggerCronTask ==================================================

func TestTriggerCronTask_TemplateMissing_RemoveAndNil(t *testing.T) {
	h := newHarness(t)
	err := h.svc.TriggerCronTask(context.Background(), "tk-missing")
	assert.NoError(t, err, "缺模板时静默；scheduler 注销防再触发")
	assert.Equal(t, []string{"tk-missing"}, h.scheduler.removed)
}

func TestTriggerCronTask_NotCron_RemoveAndNil(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleImmediate,
	})
	err := h.svc.TriggerCronTask(context.Background(), "tk-1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"tk-1"}, h.scheduler.removed)
	assert.Equal(t, 0, h.tasks.insertCall, "未派生实例")
}

func TestTriggerCronTask_Canceled_RemoveAndNil(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskCanceled, ScheduleKind: domain.ScheduleCron, CronExpr: "*/5 * * * *",
	})
	err := h.svc.TriggerCronTask(context.Background(), "tk-1")
	assert.NoError(t, err)
	assert.Equal(t, []string{"tk-1"}, h.scheduler.removed)
	assert.Equal(t, 0, h.tasks.insertCall)
}

func TestTriggerCronTask_HappyPath_CreatesInstance(t *testing.T) {
	h := newHarness(t)
	// 模板
	h.tasks.put(&domain.ScanTask{
		ID: "tk-cron", TenantID: "ten-1", ProjectID: "p-1",
		Name: "daily-scan", Kind: domain.KindPortScan, Target: "1.2.3.4", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleCron, CronExpr: "0 0 * * *",
		CreatedBy: "u-1",
	})
	// project 存在 active；dispatch 路径需要 project 在 lookup 里
	h.projects.put(&tenancydomain.Project{
		ID: "p-1", TenantID: "ten-1", Name: "p1", Status: tenancydomain.ProjectActive,
	})

	err := h.svc.TriggerCronTask(context.Background(), "tk-cron")
	require.NoError(t, err)
	assert.Equal(t, 1, h.tasks.insertCall, "Insert 调一次（实例化）")
	assert.Empty(t, h.scheduler.removed, "正常路径不注销 scheduler")

	// 找出新建的实例 task
	var instance *domain.ScanTask
	for _, x := range h.tasks.tasks {
		if x.ID != "tk-cron" {
			instance = x
			break
		}
	}
	require.NotNil(t, instance)
	expectedSuffix := fixedTime().Format("[2006-01-02 15:04]")
	assert.Contains(t, instance.Name, expectedSuffix, "实例 name 含时间后缀")
	assert.Contains(t, instance.Name, "daily-scan", "实例 name 保留模板名")
	require.NotNil(t, instance.SourceTaskID)
	assert.Equal(t, "tk-cron", *instance.SourceTaskID, "SourceTaskID 指模板")
	assert.Equal(t, domain.ScheduleImmediate, instance.ScheduleKind, "实例必须是 immediate")
	assert.Equal(t, "ten-1", instance.TenantID)
	assert.Equal(t, "p-1", instance.ProjectID)
	assert.Equal(t, "u-1", instance.CreatedBy, "沿用模板 owner")
}

// === Tests: RetryTask ========================================================

func TestRetryTask_PendingRejected(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleImmediate,
	})
	_, err := h.svc.RetryTask(context.Background(), "tk-1")
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrTaskInvalidState, code)
}

func TestRetryTask_RunningRejected(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	_, err := h.svc.RetryTask(context.Background(), "tk-1")
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrTaskInvalidState, code)
}

func TestRetryTask_FailedSucceeds(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-old", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindPortScan, Target: "1.2.3.4", TargetKind: domain.TargetIP,
		Status: domain.TaskFailed, ScheduleKind: domain.ScheduleImmediate, CreatedBy: "u-1",
	})
	h.projects.put(&tenancydomain.Project{
		ID: "p-1", TenantID: "ten-1", Name: "p1", Status: tenancydomain.ProjectActive,
	})

	got, err := h.svc.RetryTask(context.Background(), "tk-old")
	require.NoError(t, err)
	require.NotNil(t, got)
	expectedSuffix := fixedTime().Format("[retry 2006-01-02 15:04]")
	assert.Contains(t, got.Name, expectedSuffix)
	assert.Contains(t, got.Name, "scan")
	require.NotNil(t, got.SourceTaskID)
	assert.Equal(t, "tk-old", *got.SourceTaskID)
	assert.Equal(t, domain.ScheduleImmediate, got.ScheduleKind)
}

func TestRetryTask_CanceledSucceeds(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-can", TenantID: "ten-1", ProjectID: "p-1",
		Name: "scan", Kind: domain.KindWebCrawl, Target: "https://x", TargetKind: domain.TargetURL,
		Status: domain.TaskCanceled, ScheduleKind: domain.ScheduleImmediate, CreatedBy: "u-1",
	})
	h.projects.put(&tenancydomain.Project{
		ID: "p-1", TenantID: "ten-1", Name: "p1", Status: tenancydomain.ProjectActive,
	})

	got, err := h.svc.RetryTask(context.Background(), "tk-can")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Contains(t, got.Name, fixedTime().Format("[retry 2006-01-02 15:04]"))
	require.NotNil(t, got.SourceTaskID)
	assert.Equal(t, "tk-can", *got.SourceTaskID)
}

// === Tests: SweepStaleAssignments ============================================

func TestSweepStaleAssignments_ZeroTimeoutRejected(t *testing.T) {
	h := newHarness(t)
	n, err := h.svc.SweepStaleAssignments(context.Background(), 0)
	assert.Equal(t, 0, n)
	require.Error(t, err)
	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestSweepStaleAssignments_NoStale_ReturnsZero(t *testing.T) {
	h := newHarness(t)
	n, err := h.svc.SweepStaleAssignments(context.Background(), 5*time.Minute)
	assert.NoError(t, err)
	assert.Equal(t, 0, n)
	assert.Empty(t, h.assignments.updateStatusLog)
}

func TestSweepStaleAssignments_MultiStale_MarkAllFailed_AggregatesTasks(t *testing.T) {
	h := newHarness(t)
	// 3 个 stale 派发；其中 2 个属同一 task → 聚合应去重
	h.tasks.put(&domain.ScanTask{
		ID: "tk-A", TenantID: "ten-1", ProjectID: "p-1",
		Name: "tA", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	h.tasks.put(&domain.ScanTask{
		ID: "tk-B", TenantID: "ten-1", ProjectID: "p-1",
		Name: "tB", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	// 3 个 stale 派发先 put 进 rows，让 UpdateStatus 找得到
	h.assignments.put(&domain.TaskAssignment{ID: "as-1", TaskID: "tk-A", NodeID: "n1", Status: domain.AssignmentRunning})
	h.assignments.put(&domain.TaskAssignment{ID: "as-2", TaskID: "tk-A", NodeID: "n2", Status: domain.AssignmentRunning})
	h.assignments.put(&domain.TaskAssignment{ID: "as-3", TaskID: "tk-B", NodeID: "n3", Status: domain.AssignmentPulled})
	// 让 ListStaleRunning 返这 3 条
	h.assignments.staleList = []*domain.TaskAssignment{
		{ID: "as-1", TaskID: "tk-A"},
		{ID: "as-2", TaskID: "tk-A"},
		{ID: "as-3", TaskID: "tk-B"},
	}

	n, err := h.svc.SweepStaleAssignments(context.Background(), 30*time.Second)
	require.NoError(t, err)
	assert.Equal(t, 3, n)
	require.Len(t, h.assignments.updateStatusLog, 3)
	for _, u := range h.assignments.updateStatusLog {
		assert.Equal(t, domain.AssignmentFailed, u.Status)
		assert.Contains(t, u.ErrMsg, "timeout")
	}
	// 聚合 task：3 条 stale 全转 failed 后 aggregateTaskStatus 看到全 terminal+failed →
	// 把两个 task 各推到 failed。statusLog 至少应含 tk-A 和 tk-B 各一条。
	statusByTask := map[string]domain.TaskStatus{}
	for _, u := range h.tasks.statusLog {
		statusByTask[u.ID] = u.Status
	}
	assert.Equal(t, domain.TaskFailed, statusByTask["tk-A"])
	assert.Equal(t, domain.TaskFailed, statusByTask["tk-B"])
}

func TestSweepStaleAssignments_ListErrPropagates(t *testing.T) {
	h := newHarness(t)
	h.assignments.listStaleErr = errors.New("db down")
	n, err := h.svc.SweepStaleAssignments(context.Background(), time.Minute)
	require.Error(t, err)
	assert.Equal(t, 0, n)
}

// === Tests: aggregateTaskStatus (直接调，覆盖各状态转移) =======================

func TestAggregateTaskStatus_TaskCanceled_NoChange(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskCanceled, ScheduleKind: domain.ScheduleImmediate,
	})
	// 即使 assignments 全 failed 也不动 task
	h.assignments.put(&domain.TaskAssignment{
		ID: "as-1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentFailed,
	})
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	assert.NoError(t, err)
	assert.Empty(t, h.tasks.statusLog, "canceled task 不被聚合改写")
}

func TestAggregateTaskStatus_TaskAlreadyTerminal_NoChange(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskCompleted, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{
		ID: "as-1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentFailed,
	})
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	assert.NoError(t, err)
	assert.Empty(t, h.tasks.statusLog)
}

func TestAggregateTaskStatus_ZeroAssignments_NoChange(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleImmediate,
	})
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	assert.NoError(t, err)
	assert.Empty(t, h.tasks.statusLog)
}

func TestAggregateTaskStatus_AnyRunningOrPulled_TaskRunning(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{ID: "a1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentAssigned})
	h.assignments.put(&domain.TaskAssignment{ID: "a2", TaskID: "tk-1", NodeID: "n2", Status: domain.AssignmentPulled})
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	require.NoError(t, err)
	require.Len(t, h.tasks.statusLog, 1)
	assert.Equal(t, domain.TaskRunning, h.tasks.statusLog[0].Status)
	assert.Nil(t, h.tasks.statusLog[0].FinishedAt, "running 非终态不写 finished_at")
}

func TestAggregateTaskStatus_AllTerminalAnyFailed_TaskFailed_IncMetric(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{ID: "a1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentCompleted})
	h.assignments.put(&domain.TaskAssignment{ID: "a2", TaskID: "tk-1", NodeID: "n2", Status: domain.AssignmentFailed})

	before := testutil.ToFloat64(h.metrics.TasksTerminal.WithLabelValues(string(domain.TaskFailed)))
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	require.NoError(t, err)
	require.Len(t, h.tasks.statusLog, 1)
	assert.Equal(t, domain.TaskFailed, h.tasks.statusLog[0].Status)
	require.NotNil(t, h.tasks.statusLog[0].FinishedAt, "终态写 finished_at")
	after := testutil.ToFloat64(h.metrics.TasksTerminal.WithLabelValues(string(domain.TaskFailed)))
	assert.Equal(t, before+1, after, "TasksTerminal{failed} 应 +1")
}

func TestAggregateTaskStatus_AllCompleted_TaskCompleted_IncMetric(t *testing.T) {
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskRunning, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{ID: "a1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentCompleted})
	h.assignments.put(&domain.TaskAssignment{ID: "a2", TaskID: "tk-1", NodeID: "n2", Status: domain.AssignmentCompleted})

	before := testutil.ToFloat64(h.metrics.TasksTerminal.WithLabelValues(string(domain.TaskCompleted)))
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	require.NoError(t, err)
	require.Len(t, h.tasks.statusLog, 1)
	assert.Equal(t, domain.TaskCompleted, h.tasks.statusLog[0].Status)
	require.NotNil(t, h.tasks.statusLog[0].FinishedAt)
	after := testutil.ToFloat64(h.metrics.TasksTerminal.WithLabelValues(string(domain.TaskCompleted)))
	assert.Equal(t, before+1, after, "TasksTerminal{completed} 应 +1")
}

func TestAggregateTaskStatus_AllCanceledAssignments_NoChange(t *testing.T) {
	// 当 task 仍 running 但所有 assignment 都被取消（极少；assignment 状态机不直接支持 canceled，
	// 但 aggregator 内的 switch default 是不动作）→ 不改 task 状态。
	// 这里实测：assignment 全 completed 混入 1 个 assigned → 不是 terminal、不是 running/pulled → 全 assigned 路径 → pending。
	h := newHarness(t)
	h.tasks.put(&domain.ScanTask{
		ID: "tk-1", TenantID: "ten-1", ProjectID: "p-1",
		Name: "x", Kind: domain.KindPortScan, Target: "x", TargetKind: domain.TargetIP,
		Status: domain.TaskPending, ScheduleKind: domain.ScheduleImmediate,
	})
	h.assignments.put(&domain.TaskAssignment{ID: "a1", TaskID: "tk-1", NodeID: "n1", Status: domain.AssignmentAssigned})
	err := h.svc.aggregateTaskStatus(context.Background(), "tk-1")
	require.NoError(t, err)
	// 全 assigned → next = pending；与原状态 pending 相同 → 不写
	assert.Empty(t, h.tasks.statusLog)
}
