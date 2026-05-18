package repo

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

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

// UpsertBulkReturning PR-S57：UPSERT 后返每条 asset 的 ID + is_new 标记。
// 用 PostgreSQL 的 (xmax = 0) 表达式区分本次 INSERT 与 UPDATE：
//   - 新插入行：xmax=0
//   - 冲突 UPDATE 行：xmax 是事务 ID（非 0）
//
// 注：RETURNING 行顺序与 VALUES 不保证一致；用 (tenant,project,kind,value)
// 做匹配映射回输入位置。
func (r *pgRepo) UpsertBulkReturning(ctx context.Context, items []*domain.Asset) ([]*UpsertResult, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "asset.repo: nil pool")
	}
	if len(items) == 0 {
		return nil, nil
	}
	values := ""
	args := []any{}
	for i, it := range items {
		if err := it.ValidateForCreate(); err != nil {
			return nil, err
		}
		if i > 0 {
			values += ", "
		}
		base := i*5 + 1
		values += `($` + itoa(base) + `::uuid, $` + itoa(base+1) + `::uuid, $` +
			itoa(base+2) + `, $` + itoa(base+3) + `, $` + itoa(base+4) + `::int)`
		delta := it.ResultCount
		if delta <= 0 {
			delta = 1
		}
		args = append(args, it.TenantID, it.ProjectID, string(it.Kind), it.Value, delta)
	}
	// PR-S59：UPDATE 时 reset disappeared_at = NULL —— 资产"回归"自动清消失态
	q := `INSERT INTO assets (tenant_id, project_id, kind, value, result_count) VALUES ` +
		values + `
		ON CONFLICT (tenant_id, project_id, kind, value_sha256)
		DO UPDATE SET
			last_seen = now(),
			result_count = assets.result_count + EXCLUDED.result_count,
			disappeared_at = NULL
		RETURNING id::text, tenant_id::text, project_id::text, kind, value,
		          first_seen, last_seen, result_count, (xmax = 0) AS is_new`
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: upsert returning")
	}
	defer rows.Close()

	type rkey struct{ t, p, k, v string }
	idx := make(map[rkey]int, len(items))
	for i, it := range items {
		idx[rkey{it.TenantID, it.ProjectID, string(it.Kind), it.Value}] = i
	}
	out := make([]*UpsertResult, len(items))
	for rows.Next() {
		a := &domain.Asset{}
		var isNew bool
		if err := rows.Scan(&a.ID, &a.TenantID, &a.ProjectID, &a.Kind, &a.Value,
			&a.FirstSeen, &a.LastSeen, &a.ResultCount, &isNew); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: scan upsert returning")
		}
		key := rkey{a.TenantID, a.ProjectID, string(a.Kind), a.Value}
		if i, ok := idx[key]; ok {
			out[i] = &UpsertResult{Asset: a, IsNew: isNew}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: upsert returning rows iter")
	}
	return out, nil
}

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
			result_count = assets.result_count + EXCLUDED.result_count,
			disappeared_at = NULL`
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
	// PR-S70：精确值匹配（LookupByHost 等）。
	if v := strings.TrimSpace(f.Value); v != "" {
		args = append(args, v)
		clauses = append(clauses, "value = $"+itoa(len(args)))
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

// MarkDisappeared PR-S59：见 Repository.MarkDisappeared 注释。
func (r *pgRepo) MarkDisappeared(ctx context.Context, cutoff time.Time) ([]*domain.Asset, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "asset.repo: nil pool")
	}
	q := `UPDATE assets
	      SET disappeared_at = now()
	      WHERE last_seen < $1 AND disappeared_at IS NULL
	      RETURNING id::text, tenant_id::text, project_id::text, kind, value,
	                first_seen, last_seen, result_count`
	rows, err := r.pool.Query(ctx, q, cutoff)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: mark disappeared")
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
			return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: scan mark disappeared")
		}
		a.Kind = domain.Kind(kind)
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.repo: mark disappeared iter")
	}
	return out, nil
}

// itoa 便于 SQL placeholder 拼接。
func itoa(n int) string { return strconv.Itoa(n) }
