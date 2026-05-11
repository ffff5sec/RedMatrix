package repo

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// ResultRepository 是 scan_results 表的持久层接口（PR-S5）。
type ResultRepository interface {
	// InsertBulk 一次性写多条；空切片 → no-op。
	InsertBulk(ctx context.Context, items []*domain.ScanResult) error

	// InsertBulkTx 同 InsertBulk 但在 caller 传入的 pgx.Tx 上执行（PR-S17-OUTB）。
	// 让 ReportResults 能把 INSERT + eventbus.PublishTx 放同一 PG 事务内原子提交。
	InsertBulkTx(ctx context.Context, tx pgx.Tx, items []*domain.ScanResult) error

	// ListByTask 详情页：列任务全部结果（按 created_at ASC）。
	ListByTask(ctx context.Context, taskID string) ([]*domain.ScanResult, error)

	// CountByTaskIDs 列表页一次拉所有 task 的结果计数（map[taskID]count）。
	CountByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error)
}
