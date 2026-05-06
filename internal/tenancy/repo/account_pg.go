package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// pgAccountRepo 用 pgxpool 实现 AccountRepository。
type pgAccountRepo struct {
	pool *pgxpool.Pool
}

// NewAccountPG 构造 PG-backed AccountRepository。
func NewAccountPG(pool *pgxpool.Pool) AccountRepository {
	return &pgAccountRepo{pool: pool}
}

// selectAccountSQL 列序与 scanAccount 必须保持一致。
const selectAccountSQL = `
SELECT id::text,
       slug,
       display_name,
       plan,
       status,
       quota_users,
       quota_projects,
       quota_assets,
       settings,
       created_at,
       updated_at,
       deleted_at
FROM accounts
`

// === Insert ===

func (r *pgAccountRepo) Insert(ctx context.Context, a *domain.Account) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := a.ValidateForCreate(); err != nil {
		return err
	}

	settings := a.Settings
	if settings == nil {
		settings = map[string]any{}
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "tenancy.repo: marshal settings")
	}

	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	if a.UpdatedAt.IsZero() {
		a.UpdatedAt = now
	}

	// id 可选：caller 显式指定（bootstrap 固定 UUID）或交给 DB 默认 gen_random_uuid()
	var (
		row pgx.Row
	)
	if a.ID != "" {
		row = r.pool.QueryRow(ctx, `
			INSERT INTO accounts (
				id, slug, display_name, plan, status,
				quota_users, quota_projects, quota_assets,
				settings, created_at, updated_at
			) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)
			RETURNING id::text
		`,
			a.ID, a.Slug, a.DisplayName, a.Plan, string(a.Status),
			a.QuotaUsers, a.QuotaProjects, a.QuotaAssets,
			string(settingsJSON), a.CreatedAt, a.UpdatedAt,
		)
	} else {
		row = r.pool.QueryRow(ctx, `
			INSERT INTO accounts (
				slug, display_name, plan, status,
				quota_users, quota_projects, quota_assets,
				settings, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
			RETURNING id::text
		`,
			a.Slug, a.DisplayName, a.Plan, string(a.Status),
			a.QuotaUsers, a.QuotaProjects, a.QuotaAssets,
			string(settingsJSON), a.CreatedAt, a.UpdatedAt,
		)
	}
	if err := row.Scan(&a.ID); err != nil {
		if isUniqueViolation(err, "accounts_slug_uniq") {
			return errx.New(errx.ErrAccountSlugExists, "slug 已存在").
				WithFields("slug", a.Slug)
		}
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: insert account").
			WithFields("slug", a.Slug)
	}
	return nil
}

// === GetByID / GetBySlug / ListActive ===

func (r *pgAccountRepo) GetByID(ctx context.Context, id string) (*domain.Account, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectAccountSQL+`WHERE id = $1::uuid`, id)
	return scanAccount(row, "account_id", id)
}

func (r *pgAccountRepo) GetBySlug(ctx context.Context, slug string) (*domain.Account, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectAccountSQL+`WHERE slug = $1`, slug)
	return scanAccount(row, "slug", slug)
}

func (r *pgAccountRepo) ListActive(ctx context.Context) ([]*domain.Account, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectAccountSQL+`WHERE deleted_at IS NULL ORDER BY created_at ASC`)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list accounts")
	}
	defer rows.Close()

	var out []*domain.Account
	for rows.Next() {
		a, err := scanAccountRow(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan account")
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list accounts iter")
	}
	return out, nil
}

// === scan helpers ===

func scanAccount(row pgx.Row, lookupKey, lookupVal string) (*domain.Account, error) {
	a, err := scanAccountFields(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrAccountNotFound, "account 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan account").
			WithFields(lookupKey, lookupVal)
	}
	return a, nil
}

func scanAccountRow(rows pgx.Rows) (*domain.Account, error) {
	return scanAccountFields(rows)
}

// scanAccountFields 与 selectAccountSQL 列序严格对应。
func scanAccountFields(s interface {
	Scan(dst ...any) error
}) (*domain.Account, error) {
	a := &domain.Account{}
	var (
		status      string
		settingsRaw []byte
		deletedAt   *time.Time
	)
	if err := s.Scan(
		&a.ID, &a.Slug, &a.DisplayName, &a.Plan, &status,
		&a.QuotaUsers, &a.QuotaProjects, &a.QuotaAssets,
		&settingsRaw, &a.CreatedAt, &a.UpdatedAt, &deletedAt,
	); err != nil {
		return nil, err
	}
	a.Status = domain.AccountStatus(status)
	a.DeletedAt = deletedAt
	if len(settingsRaw) > 0 {
		if err := json.Unmarshal(settingsRaw, &a.Settings); err != nil {
			a.Settings = map[string]any{}
		}
	}
	return a, nil
}

// isUniqueViolation 判断是否 PG 唯一约束冲突（与 identity repo 同思路）。
func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	if pgErr.Code != "23505" {
		return false
	}
	if constraint == "" {
		return true
	}
	return pgErr.ConstraintName == constraint
}
