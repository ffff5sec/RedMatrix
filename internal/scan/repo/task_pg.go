package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// pgTaskRepo —— pgxpool-backed TaskRepository。
type pgTaskRepo struct {
	pool *pgxpool.Pool
}

// NewTaskPG 构造 PG 实现。
func NewTaskPG(pool *pgxpool.Pool) TaskRepository {
	return &pgTaskRepo{pool: pool}
}

const selectTaskSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       name,
       kind,
       target,
       target_kind,
       status,
       schedule_kind,
       COALESCE(cron_expr, '') AS cron_expr,
       settings,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       started_at,
       finished_at,
       deleted_at,
       source_task_id::text,
       targets,
       suite_run_id::text
FROM scan_tasks
`

func (r *pgTaskRepo) Insert(ctx context.Context, t *domain.ScanTask) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if err := t.ValidateForCreate(); err != nil {
		return err
	}
	settingsJSON, err := json.Marshal(t.Settings)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "marshal scan_task.settings")
	}
	// PR-S22：Targets 空时回填 [Target]，避免老调用与新列不一致
	targets := t.Targets
	if len(targets) == 0 && strings.TrimSpace(t.Target) != "" {
		targets = []string{t.Target}
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO scan_tasks (
			tenant_id, project_id, name, kind, target, target_kind, status,
			schedule_kind, cron_expr, settings, created_by, source_task_id, targets, suite_run_id
		) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::text[], $14)
		RETURNING id::text, created_at, updated_at
	`,
		t.TenantID, t.ProjectID, t.Name, string(t.Kind), t.Target, string(t.TargetKind),
		string(t.Status), string(t.ScheduleKind),
		nullableString(t.CronExpr), settingsJSON, nullableUUID(t.CreatedBy),
		nullableUUIDPtr(t.SourceTaskID),
		targets,
		nullableUUIDPtr(t.SuiteRunID), // PR-S23
	)
	if err := row.Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: insert task").
			WithFields("project_id", t.ProjectID, "name", t.Name)
	}
	return nil
}

func (r *pgTaskRepo) GetByID(ctx context.Context, id string) (*domain.ScanTask, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectTaskSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	t, err := scanTask(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrTaskNotFound, "task 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: get task").WithFields("id", id)
	}
	return t, nil
}

func (r *pgTaskRepo) List(ctx context.Context, f TaskFilter, p Page) ([]*domain.ScanTask, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 || p.PageSize > 200 {
		p.PageSize = 50
	}

	clauses := []string{"deleted_at IS NULL"}
	args := []any{}
	if strings.TrimSpace(f.TenantID) != "" {
		args = append(args, f.TenantID)
		clauses = append(clauses, "tenant_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(f.ProjectID) != "" {
		args = append(args, f.ProjectID)
		clauses = append(clauses, "project_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(string(f.Status)) != "" {
		args = append(args, string(f.Status))
		clauses = append(clauses, "status = $"+itoa(len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+kw+"%")
		clauses = append(clauses, "name ILIKE $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.SuiteRunID) != "" {
		args = append(args, f.SuiteRunID)
		clauses = append(clauses, "suite_run_id = $"+itoa(len(args))+"::uuid")
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	// total
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM scan_tasks `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectTaskSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list query")
	}
	defer rows.Close()

	out := []*domain.ScanTask{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list scan")
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list iter")
	}
	return out, total, nil
}

func (r *pgTaskRepo) UpdateStatus(ctx context.Context, id string, status domain.TaskStatus, finishedAt *string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if !status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "status 不合法").WithFields("got", string(status))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_tasks
		   SET status = $2,
		       finished_at = CASE WHEN $3::text IS NULL THEN finished_at ELSE now() END,
		       updated_at = now()
		 WHERE id = $1::uuid AND deleted_at IS NULL
	`, id, string(status), nullableString(toS(finishedAt)))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: update status").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "task 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgTaskRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_tasks SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
		WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: soft delete").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "task 不存在").WithFields("id", id)
	}
	return nil
}

// ListCronTemplates 列所有 schedule_kind=cron 的活跃 task 模板（PR-S12 启动期装载用）。
func (r *pgTaskRepo) ListCronTemplates(ctx context.Context) ([]CronTemplateRow, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, cron_expr
		FROM scan_tasks
		WHERE schedule_kind = 'cron'
		  AND deleted_at IS NULL
		  AND status NOT IN ('canceled')
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list cron templates")
	}
	defer rows.Close()
	out := []CronTemplateRow{}
	for rows.Next() {
		var row CronTemplateRow
		if err := rows.Scan(&row.TaskID, &row.CronExpr); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan cron row")
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// === scan helper ===

func scanTask(s interface {
	Scan(dst ...any) error
}) (*domain.ScanTask, error) {
	t := &domain.ScanTask{}
	var settingsBytes []byte
	var sourceTaskID *string
	var suiteRunID *string
	if err := s.Scan(
		&t.ID, &t.TenantID, &t.ProjectID, &t.Name,
		(*string)(&t.Kind), &t.Target, (*string)(&t.TargetKind),
		(*string)(&t.Status), (*string)(&t.ScheduleKind),
		&t.CronExpr, &settingsBytes, &t.CreatedBy,
		&t.CreatedAt, &t.UpdatedAt, &t.StartedAt, &t.FinishedAt, &t.DeletedAt,
		&sourceTaskID,
		&t.Targets,
		&suiteRunID,
	); err != nil {
		return nil, err
	}
	t.Settings = map[string]any{}
	if len(settingsBytes) > 0 {
		_ = json.Unmarshal(settingsBytes, &t.Settings)
	}
	if sourceTaskID != nil && *sourceTaskID != "" {
		t.SourceTaskID = sourceTaskID
	}
	if suiteRunID != nil && *suiteRunID != "" {
		t.SuiteRunID = suiteRunID
	}
	return t, nil
}

// === local helpers ===

func nullableUUID(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

// nullableUUIDPtr 把 *string 转 any（pgx 自动绑定 NULL）。
// 用于 source_task_id 等可空 FK 字段。
func nullableUUIDPtr(p *string) any {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return *p
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// toS 把 *string nullable 转成 string|""，便于 nullableString。
func toS(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// itoa 用 strconv 标准实现；早期版本手写 0..99 lookup，PR-S13 集成 e2e
// 暴露 InsertBulk 200 行 × 7 占位 = 1400 placeholder 时 panic。
func itoa(n int) string { return strconv.Itoa(n) }

// 占位防止 time 未用：scanTask 里 *time.Time pointer 类型由 sql 自动处理，无需 import。
var _ = time.Time{}
