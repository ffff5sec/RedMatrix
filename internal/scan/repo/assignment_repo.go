package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// AssignmentRepository 是 scan_task_assignments 表的持久层接口（PR-S2）。
type AssignmentRepository interface {
	// InsertBulk 一次性派发多条；空 → no-op。
	// task_id+node_id 已存在时 schema UNIQUE 约束 → ErrDatabase（caller 通常先去重）。
	InsertBulk(ctx context.Context, assignments []*domain.TaskAssignment) error

	// ListByTask 详情页 / 计数用。按 assigned_at ASC。
	ListByTask(ctx context.Context, taskID string) ([]*domain.TaskAssignment, error)

	// CountByTaskIDs 列表页用一次拉所有 task 的派发计数（map[taskID]count）。
	CountByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error)
}
