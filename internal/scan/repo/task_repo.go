// Package repo 是 scan 模块的持久层接口（PR-S1）。
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// TaskRepository 是 scan_tasks 表的持久层接口。
//
// 错误约定：
//   - GetByID 找不到 / 软删 → ErrTaskNotFound
//   - 其他 DB 故障 → ErrDatabase 包装
type TaskRepository interface {
	// Insert 写入新 task；要求 t.ValidateForCreate 已通过。
	Insert(ctx context.Context, t *domain.ScanTask) error

	// GetByID 按 UUID 查；不返回已软删的行。
	GetByID(ctx context.Context, id string) (*domain.ScanTask, error)

	// List 按 filter + 分页列；按 created_at DESC。
	List(ctx context.Context, filter TaskFilter, page Page) ([]*domain.ScanTask, int, error)

	// UpdateStatus 改 status；started_at / finished_at 由 caller 决定是否同步写
	// （MVP 仅 CancelTask 路径用，写 finished_at）。
	UpdateStatus(ctx context.Context, id string, status domain.TaskStatus, finishedAt *string) error

	// SoftDelete 标 deleted_at = now()。
	SoftDelete(ctx context.Context, id string) error

	// ListCronTemplates 列所有 schedule_kind=cron 且未软删 / 未取消的 task
	// 模板 ID + cron_expr。启动期 scheduler.LoadAll 用；不分页（cron task
	// MVP 数量预期 < 100）。
	ListCronTemplates(ctx context.Context) ([]CronTemplateRow, error)
}

// CronTemplateRow 启动期 LoadAll 的最小载入信息。
type CronTemplateRow struct {
	TaskID   string
	CronExpr string
}

// TaskFilter List 查询的可选过滤条件。
type TaskFilter struct {
	TenantID   string            // 必填
	ProjectID  string            // 空 = 不过滤（跨项目）
	Status     domain.TaskStatus // 空 = 不过滤
	Keyword    string            // 空 = 不过滤；name ILIKE 子串
	SuiteRunID string            // 空 = 不过滤；非空 = 只列该 suite_run 子 tasks（PR-S23）
}

// Page 分页参数（与 tenancy/repo 一致；本地复制避免跨包依赖）。
type Page struct {
	Page     int
	PageSize int
}
