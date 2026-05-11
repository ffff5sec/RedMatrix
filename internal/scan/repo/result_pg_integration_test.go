//go:build integration

// result_pg_integration_test.go: pgResultRepo 真 PG 集成测试（PR-S18-C）。
//
// 覆盖范围（result_pg.go）：
//   - InsertBulk + RETURNING 回填 ID / CreatedAt + ListByTask 往返
//   - InsertBulkTx 在传入 tx 上工作：commit 后行可见，rollback 后无（PR-S17-OUTB）
//   - CountByTaskIDs 多 task 聚合
//   - 200 行 batch INSERT 不 panic（验证 itoa 实现支持 >99 placeholder，PR-S13）
//
// fixture 与 task_pg_integration_test 共用 setupScanRepos。
package repo

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// makeAssignmentFor 派一行 assignment 给 task，返其 ID（result 必须挂 assignment）。
func makeAssignmentFor(t *testing.T, ctx context.Context, assigns AssignmentRepository, taskID, nodeID string) string {
	t.Helper()
	require.NoError(t, assigns.InsertBulk(ctx, []*domain.TaskAssignment{
		{TaskID: taskID, NodeID: nodeID, Status: domain.AssignmentRunning},
	}))
	rows, err := assigns.ListByTask(ctx, taskID)
	require.NoError(t, err)
	require.NotEmpty(t, rows)
	return rows[0].ID
}

func newResult(fix scanFixture, taskID, assignmentID string, data map[string]any) *domain.ScanResult {
	return &domain.ScanResult{
		TenantID:     fix.tenantID,
		ProjectID:    fix.projectID,
		TaskID:       taskID,
		AssignmentID: assignmentID,
		NodeID:       fix.nodeID,
		Kind:         domain.KindPortScan,
		Data:         data,
	}
}

// === InsertBulk + RETURNING + ListByTask ===

func TestResult_InsertBulk_FillsIDAndCreatedAt(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-a")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	rows := []*domain.ScanResult{
		newResult(fix, taskID, asID, map[string]any{"port": float64(22), "service": "ssh"}),
		newResult(fix, taskID, asID, map[string]any{"port": float64(80), "service": "http"}),
	}
	require.NoError(t, results.InsertBulk(ctx, rows))

	// RETURNING 回填
	for _, r := range rows {
		assert.NotEmpty(t, r.ID, "id 应被 RETURNING 回填")
		assert.False(t, r.CreatedAt.IsZero(), "created_at 应被回填")
	}

	got, err := results.ListByTask(ctx, taskID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, r := range got {
		assert.Equal(t, fix.tenantID, r.TenantID)
		assert.Equal(t, fix.projectID, r.ProjectID)
		assert.Equal(t, taskID, r.TaskID)
		assert.Equal(t, asID, r.AssignmentID)
		assert.Equal(t, domain.KindPortScan, r.Kind)
		assert.Contains(t, r.Data, "port")
	}
}

func TestResult_InsertBulk_Empty(t *testing.T) {
	_, _, results, _ := setupScanRepos(t)
	require.NoError(t, results.InsertBulk(context.Background(), nil))
	require.NoError(t, results.InsertBulk(context.Background(), []*domain.ScanResult{}))
}

func TestResult_InsertBulk_BadDomain(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-bad")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	bad := newResult(fix, taskID, asID, nil)
	bad.Kind = "not-a-kind"
	err := results.InsertBulk(ctx, []*domain.ScanResult{bad})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrTaskInvalidState, c)
}

func TestResult_ListByTask_Empty(t *testing.T) {
	tasks, _, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-empty")
	got, err := results.ListByTask(ctx, taskID)
	require.NoError(t, err)
	assert.Empty(t, got)
}

// === InsertBulkTx ===
//
// PR-S17-OUTB：service.ReportResults 在 PG 事务内 INSERT + outbox event；
// commit → 行可见 + outbox 行就绪；rollback → 都没。

func TestResult_InsertBulkTx_CommitMakesVisible(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-tx-commit")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	tx, err := fix.pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)

	rows := []*domain.ScanResult{
		newResult(fix, taskID, asID, map[string]any{"port": float64(22)}),
		newResult(fix, taskID, asID, map[string]any{"port": float64(443)}),
	}
	require.NoError(t, results.InsertBulkTx(ctx, tx, rows))
	require.NoError(t, tx.Commit(ctx))

	// commit 后行可见
	got, err := results.ListByTask(ctx, taskID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	for _, r := range rows {
		assert.NotEmpty(t, r.ID)
		assert.False(t, r.CreatedAt.IsZero())
	}
}

func TestResult_InsertBulkTx_RollbackDiscards(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-tx-rollback")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	tx, err := fix.pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)

	rows := []*domain.ScanResult{
		newResult(fix, taskID, asID, map[string]any{"port": float64(22)}),
	}
	require.NoError(t, results.InsertBulkTx(ctx, tx, rows))
	require.NoError(t, tx.Rollback(ctx))

	// rollback 后行不可见
	got, err := results.ListByTask(ctx, taskID)
	require.NoError(t, err)
	assert.Empty(t, got, "rollback 后 list 应空")
}

func TestResult_InsertBulkTx_NilTxRejected(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-tx-nil")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	rows := []*domain.ScanResult{newResult(fix, taskID, asID, nil)}
	err := results.InsertBulkTx(ctx, nil, rows)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}

func TestResult_InsertBulkTx_EmptyIsNoop(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-tx-empty")
	_ = makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	tx, err := fix.pool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	require.NoError(t, results.InsertBulkTx(ctx, tx, nil))
	require.NoError(t, results.InsertBulkTx(ctx, tx, []*domain.ScanResult{}))
}

// === CountByTaskIDs ===

func TestResult_CountByTaskIDs_Aggregates(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskA := makeTask(t, ctx, tasks, fix, "agg-a")
	taskB := makeTask(t, ctx, tasks, fix, "agg-b")
	taskC := makeTask(t, ctx, tasks, fix, "agg-c")
	asA := makeAssignmentFor(t, ctx, assigns, taskA, fix.nodeID)
	asB := makeAssignmentFor(t, ctx, assigns, taskB, fix.nodeID)
	_ = makeAssignmentFor(t, ctx, assigns, taskC, fix.nodeID)

	// taskA: 3, taskB: 1, taskC: 0
	require.NoError(t, results.InsertBulk(ctx, []*domain.ScanResult{
		newResult(fix, taskA, asA, map[string]any{"port": float64(1)}),
		newResult(fix, taskA, asA, map[string]any{"port": float64(2)}),
		newResult(fix, taskA, asA, map[string]any{"port": float64(3)}),
		newResult(fix, taskB, asB, map[string]any{"port": float64(80)}),
	}))

	counts, err := results.CountByTaskIDs(ctx, []string{taskA, taskB, taskC})
	require.NoError(t, err)
	assert.Equal(t, 3, counts[taskA])
	assert.Equal(t, 1, counts[taskB])
	_, present := counts[taskC]
	assert.False(t, present, "0 行 task 不在 map（GROUP BY 不返）")
}

func TestResult_CountByTaskIDs_Empty(t *testing.T) {
	_, _, results, _ := setupScanRepos(t)
	counts, err := results.CountByTaskIDs(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, counts)
}

// === Batch size sanity (PR-S13 itoa fix) ===
//
// 早期 itoa 实现是手写 0..99 lookup table，200 行 × 7 占位 = 1400 placeholder
// 时直接 panic。PR-S13 改用 strconv.Itoa 后此 case 必须通过。

func TestResult_InsertBulk_LargeBatchNoPanic(t *testing.T) {
	tasks, assigns, results, fix := setupScanRepos(t)
	ctx := context.Background()
	taskID := makeTask(t, ctx, tasks, fix, "res-bulk")
	asID := makeAssignmentFor(t, ctx, assigns, taskID, fix.nodeID)

	const batchSize = 200
	rows := make([]*domain.ScanResult, 0, batchSize)
	for i := 0; i < batchSize; i++ {
		rows = append(rows, newResult(fix, taskID, asID,
			map[string]any{"port": float64(1024 + i), "service": "x"}))
	}
	require.NotPanics(t, func() {
		require.NoError(t, results.InsertBulk(ctx, rows))
	})

	// 行全部插入 & RETURNING 全部回填
	for _, r := range rows {
		assert.NotEmpty(t, r.ID)
	}
	got, err := results.ListByTask(ctx, taskID)
	require.NoError(t, err)
	assert.Len(t, got, batchSize)
}
