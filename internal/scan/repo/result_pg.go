package repo

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

type pgResultRepo struct {
	pool *pgxpool.Pool
}

// NewResultPG 构造 PG 实现。
func NewResultPG(pool *pgxpool.Pool) ResultRepository {
	return &pgResultRepo{pool: pool}
}

const selectResultSQL = `
SELECT id::text,
       task_id::text,
       assignment_id::text,
       node_id::text,
       kind,
       data,
       created_at
FROM scan_results
`

func (r *pgResultRepo) InsertBulk(ctx context.Context, items []*domain.ScanResult) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if len(items) == 0 {
		return nil
	}
	values := ""
	args := []any{}
	for i, it := range items {
		if err := it.ValidateForCreate(); err != nil {
			return err
		}
		dataJSON, err := json.Marshal(it.Data)
		if err != nil {
			return errx.Wrap(errx.ErrInternal, err, "marshal result.data")
		}
		if i > 0 {
			values += ", "
		}
		base := i*5 + 1
		values += `($` + itoa(base) + `::uuid, $` + itoa(base+1) + `::uuid, $` +
			itoa(base+2) + `::uuid, $` + itoa(base+3) + `, $` + itoa(base+4) + `::jsonb)`
		args = append(args, it.TaskID, it.AssignmentID, it.NodeID, string(it.Kind), dataJSON)
	}
	q := `INSERT INTO scan_results (task_id, assignment_id, node_id, kind, data) VALUES ` + values
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: insert results")
	}
	return nil
}

func (r *pgResultRepo) ListByTask(ctx context.Context, taskID string) ([]*domain.ScanResult, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectResultSQL+`WHERE task_id = $1::uuid ORDER BY created_at ASC`, taskID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list results")
	}
	defer rows.Close()
	out := []*domain.ScanResult{}
	for rows.Next() {
		it := &domain.ScanResult{}
		var dataBytes []byte
		var kind string
		if err := rows.Scan(
			&it.ID, &it.TaskID, &it.AssignmentID, &it.NodeID,
			&kind, &dataBytes, &it.CreatedAt,
		); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan result")
		}
		it.Kind = domain.TaskKind(kind)
		it.Data = map[string]any{}
		if len(dataBytes) > 0 {
			_ = json.Unmarshal(dataBytes, &it.Data)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (r *pgResultRepo) CountByTaskIDs(ctx context.Context, taskIDs []string) (map[string]int, error) {
	out := map[string]int{}
	if r == nil || r.pool == nil {
		return out, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if len(taskIDs) == 0 {
		return out, nil
	}
	rows, err := r.pool.Query(ctx, `
		SELECT task_id::text, count(*)
		FROM scan_results
		WHERE task_id = ANY($1::uuid[])
		GROUP BY task_id
	`, taskIDs)
	if err != nil {
		return out, errx.Wrap(errx.ErrDatabase, err, "scan.repo: count results")
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
