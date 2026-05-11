//go:build integration

// task_pg_integration_test.go: pgTaskRepo 真 PG 集成测试（PR-S18-C）。
//
// 覆盖范围（task_pg.go 公共 API）：
//   - Insert + GetByID 往返（字段保真 + 默认 status=pending）
//   - SoftDelete 后 GetByID → ErrTaskNotFound
//   - List 按 status / project / keyword 过滤 + 跨 tenant 隔离
//   - ListCronTemplates 仅返活跃 cron 模板（schedule_kind=cron + 非软删 + 非 canceled）
//   - UpdateStatus 进终态时 finished_at 由 SQL CASE 自动写入
//
// 模式：testcontainers 起 PG → migrate.Up → pgxpool；每个 setup 起一个独立
// 容器（与 tenancy/repo 同模式）；container 在 t.Cleanup 内 Terminate。
package repo

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

// scanFixture 一组 tenant / project / node 公共 fixture，task / assignment / result
// 集成测试共享同 setup（避免重复跑迁移）。
type scanFixture struct {
	pool      *pgxpool.Pool
	tenantID  string
	projectID string
	nodeID    string
}

// setupScanRepos 起容器 + 跑迁移 + 插一个 account / project / node，返回所有 repo + fixture。
func setupScanRepos(t *testing.T) (TaskRepository, AssignmentRepository, ResultRepository, scanFixture) {
	t.Helper()
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, migrate.Up(ctx, db))

	pool, err := pgxpool.New(ctx, h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	fix := insertScanFixture(t, pool)
	return NewTaskPG(pool), NewAssignmentPG(pool), NewResultPG(pool), fix
}

// insertScanFixture 直接 SQL 插 account + project + node（绕开 tenancy 包；只需 FK 满足）。
func insertScanFixture(t *testing.T, pool *pgxpool.Pool) scanFixture {
	t.Helper()
	ctx := context.Background()

	var tenantID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO accounts (slug, display_name, status)
		VALUES ('alpha', 'Alpha', 'active')
		RETURNING id::text`).Scan(&tenantID))

	var projectID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO projects (tenant_id, name, status)
		VALUES ($1::uuid, 'demo', 'active')
		RETURNING id::text`, tenantID).Scan(&projectID))

	var nodeID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO nodes (tenant_id, name, status)
		VALUES ($1::uuid, 'agent-01', 'online')
		RETURNING id::text`, tenantID).Scan(&nodeID))

	return scanFixture{pool: pool, tenantID: tenantID, projectID: projectID, nodeID: nodeID}
}

func newTask(fix scanFixture, name string) *domain.ScanTask {
	return &domain.ScanTask{
		TenantID:     fix.tenantID,
		ProjectID:    fix.projectID,
		Name:         name,
		Kind:         domain.KindPortScan,
		Target:       "10.0.0.0/24",
		TargetKind:   domain.TargetCIDR,
		ScheduleKind: domain.ScheduleImmediate,
	}
}

// === Insert + GetByID ===

func TestTask_Insert_Roundtrip(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	tk := newTask(fix, "scan-a")
	tk.Settings = map[string]any{"ports": "1-1024", "concurrency": float64(20)}
	require.NoError(t, tasks.Insert(ctx, tk))
	assert.NotEmpty(t, tk.ID)
	assert.False(t, tk.CreatedAt.IsZero(), "Insert 应回填 created_at")
	assert.False(t, tk.UpdatedAt.IsZero(), "Insert 应回填 updated_at")

	got, err := tasks.GetByID(ctx, tk.ID)
	require.NoError(t, err)
	assert.Equal(t, "scan-a", got.Name)
	assert.Equal(t, domain.KindPortScan, got.Kind)
	assert.Equal(t, "10.0.0.0/24", got.Target)
	assert.Equal(t, domain.TargetCIDR, got.TargetKind)
	assert.Equal(t, domain.TaskPending, got.Status, "默认 status=pending")
	assert.Equal(t, domain.ScheduleImmediate, got.ScheduleKind)
	assert.Equal(t, "1-1024", got.Settings["ports"])
	assert.Nil(t, got.FinishedAt)
}

func TestTask_Insert_CronSetsExpr(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	tk := newTask(fix, "scan-cron")
	tk.ScheduleKind = domain.ScheduleCron
	tk.CronExpr = "*/5 * * * *"
	require.NoError(t, tasks.Insert(ctx, tk))

	got, err := tasks.GetByID(ctx, tk.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ScheduleCron, got.ScheduleKind)
	assert.Equal(t, "*/5 * * * *", got.CronExpr)
}

func TestTask_Insert_BadDomain(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	// Name 空 → 域内 ErrInvalidInput
	tk := newTask(fix, "")
	err := tasks.Insert(ctx, tk)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestTask_Insert_TenantFK(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	tk := newTask(fix, "bad-fk")
	tk.TenantID = "00000000-0000-0000-0000-000000000aaa"
	err := tasks.Insert(context.Background(), tk)
	require.Error(t, err, "tenant 不存在 → FK 违反")
}

// === SoftDelete ===

func TestTask_SoftDelete_GetByIDNotFound(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	tk := newTask(fix, "soft")
	require.NoError(t, tasks.Insert(ctx, tk))

	require.NoError(t, tasks.SoftDelete(ctx, tk.ID))

	_, err := tasks.GetByID(ctx, tk.ID)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}

func TestTask_SoftDelete_NotFound(t *testing.T) {
	tasks, _, _, _ := setupScanRepos(t)
	err := tasks.SoftDelete(context.Background(), "00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}

func TestTask_GetByID_NotFound(t *testing.T) {
	tasks, _, _, _ := setupScanRepos(t)
	_, err := tasks.GetByID(context.Background(), "00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}

// === List ===

func TestTask_List_FilterByProjectAndStatus(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	// 在 demo project 下放 3 task
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		require.NoError(t, tasks.Insert(ctx, newTask(fix, n)))
	}
	// 第二个 project 一条
	var otherProjectID string
	require.NoError(t, fix.pool.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, name, status) VALUES ($1::uuid, 'other', 'active') RETURNING id::text`,
		fix.tenantID).Scan(&otherProjectID))
	other := newTask(fix, "other-t")
	other.ProjectID = otherProjectID
	require.NoError(t, tasks.Insert(ctx, other))

	// 仅 demo project：返 3 条
	got, total, err := tasks.List(ctx,
		TaskFilter{TenantID: fix.tenantID, ProjectID: fix.projectID},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, got, 3)

	// 把一条置为 completed
	require.NoError(t, tasks.UpdateStatus(ctx, got[0].ID, domain.TaskCompleted, sptr("2026-05-11 10:00:00")))
	// 仅 pending：剩 2
	rs, total, err := tasks.List(ctx,
		TaskFilter{TenantID: fix.tenantID, ProjectID: fix.projectID, Status: domain.TaskPending},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	for _, r := range rs {
		assert.Equal(t, domain.TaskPending, r.Status)
	}
}

func TestTask_List_KeywordILIKE(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()
	for _, n := range []string{"web-scan-1", "api-scan-2", "port-3", "weekly"} {
		require.NoError(t, tasks.Insert(ctx, newTask(fix, n)))
	}
	got, total, err := tasks.List(ctx,
		TaskFilter{TenantID: fix.tenantID, Keyword: "scan"},
		Page{})
	require.NoError(t, err)
	assert.Equal(t, 2, total, "scan ILIKE 应匹配 2 条")
	assert.Len(t, got, 2)
}

func TestTask_List_TenantIsolation(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	// 另起一个 tenant + project
	var otherTenant string
	require.NoError(t, fix.pool.QueryRow(ctx,
		`INSERT INTO accounts (slug, display_name) VALUES ('bravo', 'Bravo') RETURNING id::text`).
		Scan(&otherTenant))
	var otherProject string
	require.NoError(t, fix.pool.QueryRow(ctx,
		`INSERT INTO projects (tenant_id, name) VALUES ($1::uuid, 'p2') RETURNING id::text`, otherTenant).
		Scan(&otherProject))

	// 当前 tenant 一条 + 其他 tenant 三条
	require.NoError(t, tasks.Insert(ctx, newTask(fix, "mine")))
	for _, n := range []string{"x1", "x2", "x3"} {
		tk := newTask(fix, n)
		tk.TenantID = otherTenant
		tk.ProjectID = otherProject
		require.NoError(t, tasks.Insert(ctx, tk))
	}

	got, total, err := tasks.List(ctx, TaskFilter{TenantID: fix.tenantID}, Page{})
	require.NoError(t, err)
	assert.Equal(t, 1, total, "不该看到其他 tenant 的 task")
	require.Len(t, got, 1)
	assert.Equal(t, "mine", got[0].Name)
}

func TestTask_List_DefaultPaging(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()
	for i := 0; i < 7; i++ {
		require.NoError(t, tasks.Insert(ctx, newTask(fix, "t-"+string(rune('a'+i)))))
	}
	page1, total, err := tasks.List(ctx,
		TaskFilter{TenantID: fix.tenantID},
		Page{Page: 1, PageSize: 3})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, page1, 3)

	page3, _, err := tasks.List(ctx,
		TaskFilter{TenantID: fix.tenantID},
		Page{Page: 3, PageSize: 3})
	require.NoError(t, err)
	require.Len(t, page3, 1, "7 行 / 3 大小 → 第 3 页 1 条")
}

// === ListCronTemplates ===

func TestTask_ListCronTemplates_OnlyActiveCron(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	// 1 个 immediate（不应返）
	imm := newTask(fix, "imm-1")
	require.NoError(t, tasks.Insert(ctx, imm))

	// 2 个 active cron
	c1 := newTask(fix, "cron-1")
	c1.ScheduleKind = domain.ScheduleCron
	c1.CronExpr = "0 * * * *"
	require.NoError(t, tasks.Insert(ctx, c1))

	c2 := newTask(fix, "cron-2")
	c2.ScheduleKind = domain.ScheduleCron
	c2.CronExpr = "*/15 * * * *"
	require.NoError(t, tasks.Insert(ctx, c2))

	// 1 个 cron 但已 canceled（不应返）
	c3 := newTask(fix, "cron-canceled")
	c3.ScheduleKind = domain.ScheduleCron
	c3.CronExpr = "0 6 * * *"
	require.NoError(t, tasks.Insert(ctx, c3))
	require.NoError(t, tasks.UpdateStatus(ctx, c3.ID, domain.TaskCanceled, nil))

	// 1 个 cron 但已软删（不应返）
	c4 := newTask(fix, "cron-deleted")
	c4.ScheduleKind = domain.ScheduleCron
	c4.CronExpr = "0 12 * * *"
	require.NoError(t, tasks.Insert(ctx, c4))
	require.NoError(t, tasks.SoftDelete(ctx, c4.ID))

	rows, err := tasks.ListCronTemplates(ctx)
	require.NoError(t, err)
	require.Len(t, rows, 2, "仅 2 个活跃 cron 模板")

	names := []string{rows[0].CronExpr, rows[1].CronExpr}
	assert.Contains(t, names, "0 * * * *")
	assert.Contains(t, names, "*/15 * * * *")
}

// === UpdateStatus ===

func TestTask_UpdateStatus_SetsFinishedAt(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()

	tk := newTask(fix, "lifecycle")
	require.NoError(t, tasks.Insert(ctx, tk))

	// running 不传 finishedAt
	require.NoError(t, tasks.UpdateStatus(ctx, tk.ID, domain.TaskRunning, nil))
	got, err := tasks.GetByID(ctx, tk.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.TaskRunning, got.Status)
	assert.Nil(t, got.FinishedAt, "running 时 finished_at 仍为 NULL")

	// completed 传 finishedAt 非 nil → SQL 把 finished_at 写为 now()
	require.NoError(t, tasks.UpdateStatus(ctx, tk.ID, domain.TaskCompleted, sptr("2026-05-11T10:00:00Z")))
	got, err = tasks.GetByID(ctx, tk.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.TaskCompleted, got.Status)
	require.NotNil(t, got.FinishedAt, "completed 后 finished_at 应被 SQL CASE 写入")
	assert.WithinDuration(t, time.Now(), *got.FinishedAt, 30*time.Second)
}

func TestTask_UpdateStatus_NotFound(t *testing.T) {
	tasks, _, _, _ := setupScanRepos(t)
	err := tasks.UpdateStatus(context.Background(),
		"00000000-0000-0000-0000-000000000aaa", domain.TaskRunning, nil)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}

func TestTask_UpdateStatus_InvalidValue(t *testing.T) {
	tasks, _, _, fix := setupScanRepos(t)
	ctx := context.Background()
	tk := newTask(fix, "bad-state")
	require.NoError(t, tasks.Insert(ctx, tk))
	err := tasks.UpdateStatus(ctx, tk.ID, domain.TaskStatus("bogus"), nil)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskInvalidState, c)
}

// === helper ===

func sptr(s string) *string { return &s }
