package repo

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// AssignmentRepository 是 scan_task_assignments 表的持久层接口（PR-S2 起）。
type AssignmentRepository interface {
	// InsertBulk 一次性派发多条；空 → no-op。
	// task_id+node_id 已存在时 schema UNIQUE 约束 → ErrDatabase（caller 通常先去重）。
	InsertBulk(ctx context.Context, assignments []*domain.TaskAssignment) error

	// ListByTask 详情页 / 计数用。按 assigned_at ASC。
	ListByTask(ctx context.Context, taskID string) ([]*domain.TaskAssignment, error)

	// CountByTaskIDs 列表页用一次拉所有 task 的派发计数（map[taskID]count）。
	CountByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error)

	// ===== PR-S3: Agent 拉任务 / 进度上报 =====

	// PullForNode：原子地把所有 status='assigned' 且属于 nodeID 的行
	// UPDATE 成 'pulled' + pulled_at=now，并返回更新后的行。
	// 已 pulled / running / 终态的行不动；幂等。
	PullForNode(ctx context.Context, nodeID string) ([]*domain.TaskAssignment, error)

	// GetByID 拿单条；用于状态机校验前置查询。不存在 → ErrTaskNotFound。
	GetByID(ctx context.Context, assignmentID string) (*domain.TaskAssignment, error)

	// UpdateStatus 推进 assignment 状态。
	//
	//   - status=running  → started_at=now（仅当原值 NULL 时写）
	//   - status=completed → finished_at=now；error 清空
	//   - status=failed    → finished_at=now；error=入参
	//
	// 行不存在 → ErrTaskNotFound。
	UpdateStatus(ctx context.Context, id string, status domain.AssignmentStatus, errMsg string) error

	// ListStaleRunning（PR-S14）—— sweeper 用：列所有
	// status IN ('pulled', 'running') 且 COALESCE(started_at, pulled_at, assigned_at)
	// < staleBefore 的 assignment。caller 把它们标 failed。
	ListStaleRunning(ctx context.Context, staleBefore time.Time) ([]*domain.TaskAssignment, error)
}
