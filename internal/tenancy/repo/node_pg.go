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
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// pgNodeRepo 用 pgxpool 实现 NodeRepository。
type pgNodeRepo struct {
	pool *pgxpool.Pool
}

// NewNodePG 构造 PG-backed NodeRepository。
func NewNodePG(pool *pgxpool.Pool) NodeRepository {
	return &pgNodeRepo{pool: pool}
}

const selectNodeSQL = `
SELECT id::text,
       tenant_id::text,
       name,
       version,
       capabilities,
       status,
       last_seen_at,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       deleted_at
FROM nodes
`

// === Insert ===

func (r *pgNodeRepo) Insert(ctx context.Context, n *domain.Node) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := n.ValidateForCreate(); err != nil {
		return err
	}

	caps := n.Capabilities
	if caps == nil {
		caps = []string{}
	}
	capsJSON, err := json.Marshal(caps)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "tenancy.repo: marshal capabilities")
	}

	now := time.Now().UTC()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	if n.UpdatedAt.IsZero() {
		n.UpdatedAt = now
	}

	row := r.pool.QueryRow(ctx, `
		INSERT INTO nodes (
			tenant_id, name, version, capabilities, status,
			last_seen_at, created_by, created_at, updated_at
		) VALUES ($1::uuid, $2, $3, $4::jsonb, $5, $6, $7, $8, $9)
		RETURNING id::text
	`,
		n.TenantID, n.Name, n.Version, string(capsJSON), string(n.Status),
		n.LastSeenAt, nullableUUID(n.CreatedBy), n.CreatedAt, n.UpdatedAt,
	)
	if err := row.Scan(&n.ID); err != nil {
		if isUniqueViolation(err, "nodes_tenant_name_uniq") {
			return errx.New(errx.ErrNodeNameExists, "节点名在租户内已存在").
				WithFields("tenant_id", n.TenantID, "name", n.Name)
		}
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: insert node").
			WithFields("tenant_id", n.TenantID, "name", n.Name)
	}
	return nil
}

// === GetByID / List ===

func (r *pgNodeRepo) GetByID(ctx context.Context, id string) (*domain.Node, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx,
		selectNodeSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	return scanNode(row, "node_id", id)
}

func (r *pgNodeRepo) List(ctx context.Context, f NodeFilter, p Page) ([]*domain.Node, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if p.PageSize <= 0 {
		p.PageSize = 20
	}
	if p.Page < 1 {
		p.Page = 1
	}

	conds := []string{"deleted_at IS NULL"}
	args := []any{}
	if f.TenantID != "" {
		args = append(args, f.TenantID)
		conds = append(conds, "tenant_id = $"+strconv.Itoa(len(args))+"::uuid")
	}
	if f.Status != "" {
		args = append(args, string(f.Status))
		conds = append(conds, "status = $"+strconv.Itoa(len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+escapeLike(kw)+"%")
		conds = append(conds, "name ILIKE $"+strconv.Itoa(len(args)))
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM nodes WHERE `+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list nodes count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	limitIdx := strconv.Itoa(len(args) - 1)
	offsetIdx := strconv.Itoa(len(args))
	rows, err := r.pool.Query(ctx,
		selectNodeSQL+`WHERE `+where+
			` ORDER BY created_at DESC LIMIT $`+limitIdx+` OFFSET $`+offsetIdx,
		args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list nodes")
	}
	defer rows.Close()

	out := make([]*domain.Node, 0, p.PageSize)
	for rows.Next() {
		n, err := scanNodeFields(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan node")
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list nodes iter")
	}
	return out, total, nil
}

// === UpdateStatus / SoftDelete ===

func (r *pgNodeRepo) UpdateStatus(ctx context.Context, id string, status domain.NodeStatus) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if !status.Valid() {
		return errx.New(errx.ErrInvalidInput, "status 不合法").
			WithFields("got", string(status))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE nodes
		   SET status = $2, updated_at = now()
		 WHERE id = $1::uuid AND deleted_at IS NULL
	`, id, string(status))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: update node status").
			WithFields("node_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrNodeNotFound, "node 不存在").
			WithFields("node_id", id)
	}
	return nil
}

func (r *pgNodeRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE nodes
		   SET deleted_at = COALESCE(deleted_at, now()),
		       updated_at = now()
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: soft delete node").
			WithFields("node_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrNodeNotFound, "node 不存在").
			WithFields("node_id", id)
	}
	return nil
}

// === scan helpers ===

func scanNode(row pgx.Row, lookupKey, lookupVal string) (*domain.Node, error) {
	n, err := scanNodeFields(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrNodeNotFound, "node 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan node").
			WithFields(lookupKey, lookupVal)
	}
	return n, nil
}

func scanNodeFields(s interface {
	Scan(dst ...any) error
}) (*domain.Node, error) {
	n := &domain.Node{}
	var (
		status    string
		capsRaw   []byte
		lastSeen  *time.Time
		deletedAt *time.Time
	)
	if err := s.Scan(
		&n.ID, &n.TenantID, &n.Name, &n.Version,
		&capsRaw, &status, &lastSeen,
		&n.CreatedBy,
		&n.CreatedAt, &n.UpdatedAt, &deletedAt,
	); err != nil {
		return nil, err
	}
	n.Status = domain.NodeStatus(status)
	n.LastSeenAt = lastSeen
	n.DeletedAt = deletedAt
	if len(capsRaw) > 0 {
		_ = json.Unmarshal(capsRaw, &n.Capabilities)
	}
	return n, nil
}
