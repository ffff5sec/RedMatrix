package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

type pgAssignmentRepo struct {
	pool *pgxpool.Pool
}

// NewAssignmentPG 构造 PG 实现。
func NewAssignmentPG(pool *pgxpool.Pool) AssignmentRepository {
	return &pgAssignmentRepo{pool: pool}
}

const selectAssignmentSQL = `
SELECT id::text,
       task_id::text,
       node_id::text,
       status,
       assigned_at,
       pulled_at,
       started_at,
       finished_at,
       COALESCE(error, '') AS error
FROM scan_task_assignments
`

func (r *pgAssignmentRepo) InsertBulk(ctx context.Context, items []*domain.TaskAssignment) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if len(items) == 0 {
		return nil
	}

	// 简化版 multi-row INSERT：accumulate VALUES
	values := ``
	args := []any{}
	for i, a := range items {
		if err := a.ValidateForCreate(); err != nil {
			return err
		}
		if i > 0 {
			values += ", "
		}
		base := i*3 + 1
		values += `($` + itoa(base) + `::uuid, $` + itoa(base+1) + `::uuid, $` + itoa(base+2) + `)`
		args = append(args, a.TaskID, a.NodeID, string(a.Status))
	}

	q := `INSERT INTO scan_task_assignments (task_id, node_id, status) VALUES ` + values
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: insert assignments")
	}
	return nil
}

func (r *pgAssignmentRepo) ListByTask(ctx context.Context, taskID string) ([]*domain.TaskAssignment, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectAssignmentSQL+`WHERE task_id = $1::uuid ORDER BY assigned_at ASC`,
		taskID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list assignments")
	}
	defer rows.Close()

	out := []*domain.TaskAssignment{}
	for rows.Next() {
		a := &domain.TaskAssignment{}
		var status string
		if err := rows.Scan(
			&a.ID, &a.TaskID, &a.NodeID, &status,
			&a.AssignedAt, &a.PulledAt, &a.StartedAt, &a.FinishedAt, &a.Error,
		); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan assignment")
		}
		a.Status = domain.AssignmentStatus(status)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *pgAssignmentRepo) CountByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if r == nil || r.pool == nil {
		return out, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if len(taskIDs) == 0 {
		return out, nil
	}
	// uuid[] 用 pg array 比循环 IN 更省往返；pgx 自动 marshal []string
	rows, err := r.pool.Query(ctx, `
		SELECT task_id::text, count(*)
		FROM scan_task_assignments
		WHERE task_id = ANY($1::uuid[])
		GROUP BY task_id
	`, taskIDs)
	if err != nil {
		return out, errx.Wrap(errx.ErrDatabase, err, "scan.repo: count assignments")
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return out, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan count")
		}
		out[id] = n
	}
	return out, rows.Err()
}
