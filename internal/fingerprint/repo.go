package fingerprint

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// CustomRuleRepository fingerprint_rules 表持久层。
type CustomRuleRepository interface {
	// Insert 新建；同 tenant 下 name 唯一冲突返 ErrInvalidInput。
	Insert(ctx context.Context, r *CustomRule) error

	// GetByID 取单条；不存在返 nil/nil（caller 自决）。
	GetByID(ctx context.Context, id string) (*CustomRule, error)

	// ListEnabledByTenant TenantMatcher 热路径：取该 tenant 全部 enabled 规则。
	ListEnabledByTenant(ctx context.Context, tenantID string) ([]*CustomRule, error)

	// ListAllByTenant UI 用：含 disabled，按 created_at DESC。
	ListAllByTenant(ctx context.Context, tenantID string) ([]*CustomRule, error)

	// SoftDelete 软删；同 tenant 下 name 可被新规则复用。
	SoftDelete(ctx context.Context, id string) error

	// ToggleEnabled 翻转 enabled 状态。
	ToggleEnabled(ctx context.Context, id string, enabled bool) error
}

type pgRepo struct {
	pool *pgxpool.Pool
}

// NewPGRepo 构造 PG 实现。
func NewPGRepo(pool *pgxpool.Pool) CustomRuleRepository {
	return &pgRepo{pool: pool}
}

const ruleSelectSQL = `
SELECT id::text, tenant_id::text, name, fields, keyword, case_sensitive,
       enabled, description, created_by::text, created_at, updated_at
FROM fingerprint_rules
`

func (r *pgRepo) Insert(ctx context.Context, c *CustomRule) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	if err := c.ValidateForCreate(); err != nil {
		return err
	}
	var createdBy any
	if c.CreatedBy != nil && *c.CreatedBy != "" {
		createdBy = *c.CreatedBy
	}
	err := r.pool.QueryRow(ctx, `
INSERT INTO fingerprint_rules
  (tenant_id, name, fields, keyword, case_sensitive, enabled, description, created_by)
VALUES ($1::uuid, $2, $3::text[], $4, $5, $6, $7, $8)
RETURNING id::text, created_at, updated_at
`,
		c.TenantID, c.Name, c.Fields, c.Keyword,
		c.CaseSensitive, c.Enabled, c.Description, createdBy,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		// unique 冲突更易读
		if strings.Contains(err.Error(), "idx_fp_rules_tenant_name") {
			return errx.New(errx.ErrInvalidInput, "同名规则已存在").
				WithFields("tenant_id", c.TenantID, "name", c.Name)
		}
		return errx.Wrap(errx.ErrDatabase, err, "fingerprint.repo: insert")
	}
	return nil
}

func (r *pgRepo) GetByID(ctx context.Context, id string) (*CustomRule, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	q := ruleSelectSQL + " WHERE id = $1::uuid AND deleted_at IS NULL"
	c, err := scanOne(r.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil //nolint:nilnil // 不存在 = 正常 no-match
		}
		return nil, err
	}
	return c, nil
}

func (r *pgRepo) ListEnabledByTenant(ctx context.Context, tenantID string) ([]*CustomRule, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	q := ruleSelectSQL + " WHERE tenant_id = $1::uuid AND deleted_at IS NULL AND enabled = TRUE ORDER BY name ASC"
	return scanMany(ctx, r.pool, q, tenantID)
}

func (r *pgRepo) ListAllByTenant(ctx context.Context, tenantID string) ([]*CustomRule, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	q := ruleSelectSQL + " WHERE tenant_id = $1::uuid AND deleted_at IS NULL ORDER BY created_at DESC"
	return scanMany(ctx, r.pool, q, tenantID)
}

func (r *pgRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE fingerprint_rules SET deleted_at = now(), updated_at = now() WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "fingerprint.repo: soft delete")
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule 不存在或已删除").WithFields("id", id)
	}
	return nil
}

func (r *pgRepo) ToggleEnabled(ctx context.Context, id string, enabled bool) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "fingerprint.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE fingerprint_rules SET enabled = $2, updated_at = now() WHERE id = $1::uuid AND deleted_at IS NULL`,
		id, enabled)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "fingerprint.repo: toggle enabled")
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrInvalidInput, "fingerprint rule 不存在或已删除").WithFields("id", id)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOne(row rowScanner) (*CustomRule, error) {
	c := &CustomRule{}
	var createdBy *string
	if err := row.Scan(
		&c.ID, &c.TenantID, &c.Name, &c.Fields, &c.Keyword,
		&c.CaseSensitive, &c.Enabled, &c.Description, &createdBy,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "fingerprint.repo: scan")
	}
	c.CreatedBy = createdBy
	return c, nil
}

func scanMany(ctx context.Context, pool *pgxpool.Pool, q string, args ...any) ([]*CustomRule, error) {
	rows, err := pool.Query(ctx, q, args...)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "fingerprint.repo: query")
	}
	defer rows.Close()
	out := []*CustomRule{}
	for rows.Next() {
		c, err := scanOne(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
