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

// === PR-S3 ===

func (r *pgAssignmentRepo) PullForNode(ctx context.Context, nodeID string) ([]*domain.TaskAssignment, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		WITH updated AS (
			UPDATE scan_task_assignments
			   SET status = 'pulled', pulled_at = now()
			 WHERE node_id = $1::uuid AND status = 'assigned'
			RETURNING id
		)
		`+selectAssignmentSQL+`
		WHERE id IN (SELECT id FROM updated)
		ORDER BY assigned_at ASC
	`, nodeID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: pull for node").
			WithFields("node_id", nodeID)
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
			return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan pulled")
		}
		a.Status = domain.AssignmentStatus(status)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (r *pgAssignmentRepo) GetByID(ctx context.Context, id string) (*domain.TaskAssignment, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectAssignmentSQL+`WHERE id = $1::uuid`, id)
	a := &domain.TaskAssignment{}
	var status string
	if err := row.Scan(
		&a.ID, &a.TaskID, &a.NodeID, &status,
		&a.AssignedAt, &a.PulledAt, &a.StartedAt, &a.FinishedAt, &a.Error,
	); err != nil {
		return nil, errx.New(errx.ErrTaskNotFound, "assignment 不存在").
			WithFields("id", id)
	}
	a.Status = domain.AssignmentStatus(status)
	return a, nil
}

func (r *pgAssignmentRepo) UpdateStatus(ctx context.Context, id string, status domain.AssignmentStatus, errMsg string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if !status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "status 不合法").
			WithFields("got", string(status))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_task_assignments
		   SET status = $2::varchar,
		       started_at  = CASE WHEN $2::varchar = 'running'  AND started_at IS NULL THEN now() ELSE started_at END,
		       finished_at = CASE WHEN $2::varchar IN ('completed','failed') THEN now() ELSE finished_at END,
		       error       = CASE WHEN $2::varchar = 'failed' THEN $3::text ELSE NULL END
		 WHERE id = $1::uuid
	`, id, string(status), errMsg)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: update assignment status").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "assignment 不存在").WithFields("id", id)
	}
	return nil
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
