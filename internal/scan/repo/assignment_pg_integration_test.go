//go:build integration

// assignment_pg_integration_test.go: pgAssignmentRepo 真 PG 集成测试（PR-S18-C）。
//
// 覆盖范围（assignment_pg.go）：
//   - InsertBulk 多条 → ListByTask 返回 + 按 assigned_at ASC
//   - PullForNode 原子翻转 assigned→pulled（精确一行；幂等再调返 0）
//   - UpdateStatusByNode 正常路径 / 不匹配 node_id 返 NotFound / 已终态返 NotFound（PR-S17-RACE）
//   - ListStaleRunning 阈值过滤（pulled/running 且 < staleBefore）
//   - CountByTaskIDs 多 task 聚合
//
// fixture 与 task_pg_integration_test 共用 setupScanRepos / insertScanFixture。
package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// insertTestNode SQL 直插一行 node + 返 id，避开 tenancy 包；FK 用。
func insertTestNode(t *testing.T, fix scanFixture, name string) string {
	t.Helper()
	var id string
	require.NoError(t, fix.pool.QueryRow(context.Background(), `
		INSERT INTO nodes (tenant_id, name, status)
		VALUES ($1::uuid, $2, 'online')
		RETURNING id::text`, fix.tenantID, name).Scan(&id))
	return id
}

func newAssignment(taskID, nodeID string) *domain.TaskAssignment {
	return &domain.TaskAssignment{
		TaskID: taskID,
		NodeID: nodeID,
		Status: domain.AssignmentAssigned,
	}
}

// makeTask 把一个 pending task 落库返 ID（供 assignment / result FK）。
func makeTask(t *testing.T, ctx context.Context, tasks TaskRepository, fix scanFixture, name string) string {
	t.Helper()
	tk := newTask(fix, name)
	require.NoError(t, tasks.Insert(ctx, tk))
	return tk.ID
}

// === InsertBulk + ListByTask ===

func TestAssignment_InsertBulkRoundtrip(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-x")
	node1 := fix.nodeID
	node2 := insertTestNode(t, fix, "agent-02")

	items := []*domain.TaskAssignment{
		newAssignment(taskID, node1),
		newAssignment(taskID, node2),
	}
	require.NoError(t, assigns.InsertBulk(ctx, items))

	got, err := assigns.ListByTask(ctx, taskID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, a := range got {
		assert.NotEmpty(t, a.ID)
		assert.Equal(t, taskID, a.TaskID)
		assert.Equal(t, domain.AssignmentAssigned, a.Status)
		assert.False(t, a.AssignedAt.IsZero())
		assert.Nil(t, a.PulledAt)
	}
}

func TestAssignment_InsertBulkEmpty(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	// 空切片应是 no-op
	require.NoError(t, assigns.InsertBulk(context.Background(), nil))
	require.NoError(t, assigns.InsertBulk(context.Background(), []*domain.TaskAssignment{}))
}

func TestAssignment_InsertBulk_BadDomain(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-bad")
	// 第二个空 node_id → ValidateForCreate 应拒
	items := []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
		{TaskID: taskID, NodeID: "", Status: domain.AssignmentAssigned},
	}
	err := assigns.InsertBulk(ctx, items)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestAssignment_ListByTask_Empty(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-empty")
	got, err := assigns.ListByTask(ctx, taskID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// === PullForNode ===

func TestAssignment_PullForNode_FlipsAssignedToPulled(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()

	taskA := makeTask(t, ctx, tasks, fix, "scan-a")
	taskB := makeTask(t, ctx, tasks, fix, "scan-b")
	node1 := fix.nodeID
	node2 := insertTestNode(t, fix, "agent-02")

	// node1 拿 2 个 assigned 行；node2 拿 1 个
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskA, node1),
		newAssignment(taskB, node1),
		newAssignment(taskA, node2),
	}))

	// node1 pull → 应翻 2 行 assigned→pulled，不动 node2
	pulled, err := assigns.PullForNode(ctx, node1)
	require.NoError(t, err)
	require.Len(t, pulled, 2, "node1 应拿到 2 行")
	for _, a := range pulled {
		assert.Equal(t, domain.AssignmentPulled, a.Status)
		assert.Equal(t, node1, a.NodeID)
		require.NotNil(t, a.PulledAt, "pulled_at 应被填充")
	}

	// node2 行不应被动
	rs, err := assigns.ListByTask(ctx, taskA)
	require.NoError(t, err)
	var node2Row *domain.TaskAssignment
	for _, a := range rs {
		if a.NodeID == node2 {
			node2Row = a
			break
		}
	}
	require.NotNil(t, node2Row)
	assert.Equal(t, domain.AssignmentAssigned, node2Row.Status)
	assert.Nil(t, node2Row.PulledAt)
}

func TestAssignment_PullForNode_Idempotent(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-idem")
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
	}))

	// 第一次 pull 返 1
	pulled, err := assigns.PullForNode(ctx, fix.nodeID)
	require.NoError(t, err)
	require.Len(t, pulled, 1)

	// 第二次 pull 应空（已是 pulled，不会再翻）
	again, err := assigns.PullForNode(ctx, fix.nodeID)
	require.NoError(t, err)
	assert.Empty(t, again, "重复 pull 应返空（幂等）")
}

func TestAssignment_PullForNode_EmptyForUnknownNode(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	rs, err := assigns.PullForNode(context.Background(),
		"00000000-0000-0000-0000-000000000aaa")
	require.NoError(t, err)
	assert.Empty(t, rs)
}

// === UpdateStatusByNode (PR-S17-RACE) ===

func TestAssignment_UpdateStatusByNode_OKPath(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-upd")
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
	}))
	rows, err := assigns.ListByTask(ctx, taskID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	asID := rows[0].ID

	// 正常路径：assigned → running 返 taskID
	got, err := assigns.UpdateStatusByNode(ctx, asID, fix.nodeID, domain.AssignmentRunning, "")
	require.NoError(t, err)
	assert.Equal(t, taskID, got)

	a, err := assigns.GetByID(ctx, asID)
	require.NoError(t, err)
	assert.Equal(t, domain.AssignmentRunning, a.Status)
	require.NotNil(t, a.StartedAt)
}

func TestAssignment_UpdateStatusByNode_WrongNodeReturnsNotFound(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-wrongnode")
	owner := fix.nodeID
	imposter := insertTestNode(t, fix, "imposter")

	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, owner),
	}))
	rows, _ := assigns.ListByTask(ctx, taskID)
	require.Len(t, rows, 1)
	asID := rows[0].ID

	// imposter 试图改 owner 的 assignment → NotFound（不泄露存在性）
	_, err := assigns.UpdateStatusByNode(ctx, asID, imposter, domain.AssignmentCompleted, "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)

	// owner 自己的行未被动
	a, err := assigns.GetByID(ctx, asID)
	require.NoError(t, err)
	assert.Equal(t, domain.AssignmentAssigned, a.Status)
}

func TestAssignment_UpdateStatusByNode_TerminalRejects(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-terminal")
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
	}))
	rows, _ := assigns.ListByTask(ctx, taskID)
	asID := rows[0].ID

	// 先标 completed
	_, err := assigns.UpdateStatusByNode(ctx, asID, fix.nodeID, domain.AssignmentCompleted, "")
	require.NoError(t, err)

	// 再来一次 failed 应拒（已终态 → NotFound）
	_, err = assigns.UpdateStatusByNode(ctx, asID, fix.nodeID, domain.AssignmentFailed, "second")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c, "终态不能再翻 → NotFound（PR-S17-RACE）")

	// 行仍是 completed（且 error 字段空）
	a, err := assigns.GetByID(ctx, asID)
	require.NoError(t, err)
	assert.Equal(t, domain.AssignmentCompleted, a.Status)
	assert.Empty(t, a.Error)
}

func TestAssignment_UpdateStatusByNode_InvalidStatus(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	_, err := assigns.UpdateStatusByNode(context.Background(),
		"00000000-0000-0000-0000-000000000aaa",
		"00000000-0000-0000-0000-000000000aaa",
		domain.AssignmentStatus("bogus"), "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskInvalidState, c)
}

// === UpdateStatus (legacy) ===

func TestAssignment_UpdateStatus_FailedFillsError(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-fail")
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
	}))
	rows, _ := assigns.ListByTask(ctx, taskID)
	asID := rows[0].ID

	require.NoError(t, assigns.UpdateStatus(ctx, asID, domain.AssignmentFailed, "boom"))
	a, err := assigns.GetByID(ctx, asID)
	require.NoError(t, err)
	assert.Equal(t, domain.AssignmentFailed, a.Status)
	assert.Equal(t, "boom", a.Error)
	require.NotNil(t, a.FinishedAt)
}

func TestAssignment_UpdateStatus_NotFound(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	err := assigns.UpdateStatus(context.Background(),
		"00000000-0000-0000-0000-000000000aaa", domain.AssignmentRunning, "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}

// === ListStaleRunning ===

func TestAssignment_ListStaleRunning_ThresholdFiltering(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-stale")

	// 3 行：fresh assigned / stale pulled / stale running
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
		newAssignment(taskID, insertTestNode(t, fix, "agent-2")),
		newAssignment(taskID, insertTestNode(t, fix, "agent-3")),
	}))
	rows, _ := assigns.ListByTask(ctx, taskID)
	require.Len(t, rows, 3)

	// 把 rows[1] 强制 pulled + 老时间；rows[2] 强制 running + 老时间
	old := time.Now().UTC().Add(-2 * time.Hour)
	_, err := fix.pool.Exec(ctx, `
		UPDATE scan_task_assignments SET status='pulled', pulled_at=$2, assigned_at=$2
		WHERE id = $1::uuid`, rows[1].ID, old)
	require.NoError(t, err)
	_, err = fix.pool.Exec(ctx, `
		UPDATE scan_task_assignments SET status='running', started_at=$2, assigned_at=$2
		WHERE id = $1::uuid`, rows[2].ID, old)
	require.NoError(t, err)

	// 阈值 = 1 小时前；预期 stale 拿到 2 行
	cutoff := time.Now().UTC().Add(-time.Hour)
	stale, err := assigns.ListStaleRunning(ctx, cutoff)
	require.NoError(t, err)
	require.Len(t, stale, 2)
	ids := map[string]bool{}
	for _, a := range stale {
		ids[a.ID] = true
	}
	assert.True(t, ids[rows[1].ID])
	assert.True(t, ids[rows[2].ID])
	assert.False(t, ids[rows[0].ID], "fresh assigned 不应入选")
}

func TestAssignment_ListStaleRunning_NoneStale(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "scan-fresh")
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskID, fix.nodeID),
	}))
	stale, err := assigns.ListStaleRunning(ctx, time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, stale, "全新插入 + assigned 不应入 stale 范围")
}

// === CountByTaskIDs ===

func TestAssignment_CountByTaskIDs_Aggregates(t *testing.T) {
	tasks, assigns, _, fix := setupScanRepos(t)
	ctx := context.Background()
	taskA := makeTask(t, ctx, tasks, fix, "agg-a")
	taskB := makeTask(t, ctx, tasks, fix, "agg-b")
	taskC := makeTask(t, ctx, tasks, fix, "agg-c")
	node1 := fix.nodeID
	node2 := insertTestNode(t, fix, "n2")
	node3 := insertTestNode(t, fix, "n3")

	// A: 2; B: 1; C: 0
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		newAssignment(taskA, node1),
		newAssignment(taskA, node2),
		newAssignment(taskB, node3),
	}))

	counts, err := assigns.CountByTaskIDs(ctx, []string{taskA, taskB, taskC})
	require.NoError(t, err)
	assert.Equal(t, 2, counts[taskA])
	assert.Equal(t, 1, counts[taskB])
	_, present := counts[taskC]
	assert.False(t, present, "taskC 无 assignment，不应出现在 map（GROUP BY 不返）")
}

func TestAssignment_CountByTaskIDs_Empty(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	counts, err := assigns.CountByTaskIDs(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

// === GetByID ===

func TestAssignment_GetByID_NotFound(t *testing.T) {
	_, assigns, _, _ := setupScanRepos(t)
	_, err := assigns.GetByID(context.Background(),
		"00000000-0000-0000-0000-000000000aaa")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskNotFound, c)
}
