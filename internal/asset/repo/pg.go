package repo

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

type pgRepo struct {
	pool *pgxpool.Pool
}

// NewPG 构造 PG 实现。
func NewPG(pool *pgxpool.Pool) Repository {
	return &pgRepo{pool: pool}
}

const selectSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       kind,
       value,
       first_seen,
       last_seen,
       result_count
FROM assets
`

func (r *pgRepo) UpsertBulk(ctx context.Context, items []*domain.Asset) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "asset.repo: nil pool")
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
		if i > 0 {
			values += ", "
		}
		base := i*5 + 1
		// (tenant_id, project_id, kind, value, delta_count)
		values += `($` + itoa(base) + `::uuid, $` + itoa(base+1) + `::uuid, $` +
			itoa(base+2) + `, $` + itoa(base+3) + `, $` + itoa(base+4) + `::int)`
		delta := it.ResultCount
		if delta <= 0 {
			delta = 1
		}
		args = append(args, it.TenantID, it.ProjectID, string(it.Kind), it.Value, delta)
	}
	// PR-S18-B：冲突列改为 (tenant_id, project_id, kind, value_sha256) —— 索引
	// idx_assets_unique_hash；value_sha256 由 BEFORE INSERT trigger 自动从 value 算。
	// 这样长 URL（接近 VARCHAR(2048)）不会触发 btree 行 size 上限。
	q := `INSERT INTO assets (tenant_id, project_id, kind, value, result_count) VALUES ` +
		values + `
		ON CONFLICT (tenant_id, project_id, kind, value_sha256)
		DO UPDATE SET
			last_seen = now(),
			result_count = assets.result_count + EXCLUDED.result_count`
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "asset.repo: upsert")
	}
	return nil
}

func (r *pgRepo) List(ctx context.Context, f Filter, p Page) ([]*domain.Asset, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "asset.repo: nil pool")
	}
	clauses := []string{}
	args := []any{}
	if v := strings.TrimSpace(f.TenantID); v != "" {
		args = append(args, v)
		clauses = append(clauses, "tenant_id = $"+itoa(len(args))+"::uuid")
	}
	if v := strings.TrimSpace(f.ProjectID); v != "" {
		args = append(args, v)
		clauses = append(clauses, "project_id = $"+itoa(len(args))+"::uuid")
	} else if f.ProjectIDs != nil {
		// PA 路径：明确传入空切片应由 caller 短路；这里防御加一个总不可能命中条件
		if len(f.ProjectIDs) == 0 {
			return []*domain.Asset{}, 0, nil
		}
		args = append(args, f.ProjectIDs)
		clauses = append(clauses, "project_id = ANY($"+itoa(len(args))+"::uuid[])")
	}
	if f.Kind != "" {
		args = append(args, string(f.Kind))
		clauses = append(clauses, "kind = $"+itoa(len(args)))
	}
	if v := strings.TrimSpace(f.Keyword); v != "" {
		args = append(args, "%"+v+"%")
		clauses = append(clauses, "value ILIKE $"+itoa(len(args)))
	}
	if f.LastSeenBefore != nil {
		args = append(args, *f.LastSeenBefore)
		clauses = append(clauses, "last_seen < $"+itoa(len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// total
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM assets`+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.repo: count")
	}

	page, size := p.Page, p.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 || size > 200 {
		size = 50
	}
	args = append(args, size, (page-1)*size)
	rows, err := r.pool.Query(ctx,
		selectSQL+where+` ORDER BY last_seen DESC LIMIT $`+itoa(len(args)-1)+` OFFSET $`+itoa(len(args)),
		args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.repo: list")
	}
	defer rows.Close()
	out := []*domain.Asset{}
	for rows.Next() {
		a := &domain.Asset{}
		var kind string
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.ProjectID, &kind, &a.Value,
			&a.FirstSeen, &a.LastSeen, &a.ResultCount,
		); err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.repo: scan")
		}
		a.Kind = domain.Kind(kind)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

func (r *pgRepo) GetByID(ctx context.Context, id string) (*domain.Asset, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "asset.repo: nil pool")
	}
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "asset.id 不能为空")
	}
	a := &domain.Asset{}
	var kind string
	err := r.pool.QueryRow(ctx, selectSQL+` WHERE id = $1::uuid`, id).Scan(
		&a.ID, &a.TenantID, &a.ProjectID, &kind, &a.Value,
		&a.FirstSeen, &a.LastSeen, &a.ResultCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errx.New(errx.ErrAssetNotFound, "asset 不存在").
				WithFields("id", id)
		}
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: get")
	}
	a.Kind = domain.Kind(kind)
	return a, nil
}

// itoa 便于 SQL placeholder 拼接。
func itoa(n int) string { return strconv.Itoa(n) }
