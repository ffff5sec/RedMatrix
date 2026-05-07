package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// pgRegistrationTokenRepo 用 pgxpool 实现 RegistrationTokenRepository。
type pgRegistrationTokenRepo struct {
	pool *pgxpool.Pool
}

// NewRegistrationTokenPG 构造 PG-backed 实现。
func NewRegistrationTokenPG(pool *pgxpool.Pool) RegistrationTokenRepository {
	return &pgRegistrationTokenRepo{pool: pool}
}

const selectRegistrationTokenSQL = `
SELECT id::text,
       tenant_id::text,
       name,
       token_hash,
       expires_at,
       used_at,
       revoked_at,
       COALESCE(created_by::text, '') AS created_by,
       created_at
FROM registration_tokens
`

// === Insert ===

func (r *pgRegistrationTokenRepo) Insert(ctx context.Context, t *domain.RegistrationToken) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := t.ValidateForCreate(); err != nil {
		return err
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO registration_tokens (
			tenant_id, name, token_hash, expires_at,
			used_at, revoked_at, created_by, created_at
		) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id::text
	`,
		t.TenantID, t.Name, t.TokenHash, t.ExpiresAt,
		nullableTime(t.UsedAt), nullableTime(t.RevokedAt),
		nullableUUID(t.CreatedBy), t.CreatedAt,
	)
	if err := row.Scan(&t.ID); err != nil {
		// hash 冲突理论上不可能（32 字节随机），但万一中招也走 invalid 错码
		if isUniqueViolation(err, "registration_tokens_hash_uniq") {
			return errx.New(errx.ErrNodeRegistrationTokenInvalid,
				"token hash 冲突；请重试").WithFields("name", t.Name)
		}
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: insert registration token").
			WithFields("name", t.Name)
	}
	return nil
}

// === GetByHash / GetByID / List ===

func (r *pgRegistrationTokenRepo) GetByHash(ctx context.Context, hash string) (*domain.RegistrationToken, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectRegistrationTokenSQL+`WHERE token_hash = $1`, hash)
	return scanRegistrationToken(row, "token_hash", "***")
}

func (r *pgRegistrationTokenRepo) GetByID(ctx context.Context, id string) (*domain.RegistrationToken, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectRegistrationTokenSQL+`WHERE id = $1::uuid`, id)
	return scanRegistrationToken(row, "token_id", id)
}

func (r *pgRegistrationTokenRepo) ListByTenant(ctx context.Context, tenantID string) ([]*domain.RegistrationToken, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectRegistrationTokenSQL+`WHERE tenant_id = $1::uuid ORDER BY created_at DESC`,
		tenantID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list registration tokens").
			WithFields("tenant_id", tenantID)
	}
	defer rows.Close()

	var out []*domain.RegistrationToken
	for rows.Next() {
		t, err := scanRegistrationTokenRow(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan registration token")
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list registration tokens iter")
	}
	return out, nil
}

// === Revoke / MarkUsed ===

func (r *pgRegistrationTokenRepo) Revoke(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE registration_tokens
		   SET revoked_at = COALESCE(revoked_at, now())
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: revoke registration token").
			WithFields("token_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrNodeRegistrationTokenInvalid, "token 不存在").
			WithFields("token_id", id)
	}
	return nil
}

// MarkUsed 仅当 used_at IS NULL AND revoked_at IS NULL 时才生效；防双花。
func (r *pgRegistrationTokenRepo) MarkUsed(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE registration_tokens
		   SET used_at = now()
		 WHERE id = $1::uuid
		   AND used_at IS NULL
		   AND revoked_at IS NULL
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: mark used").
			WithFields("token_id", id)
	}
	if tag.RowsAffected() == 0 {
		// 行不存在 / 已用 / 已撤 都返同一码（防侧信道）
		return errx.New(errx.ErrNodeRegistrationTokenInvalid, "token 不可用").
			WithFields("token_id", id)
	}
	return nil
}

// === scan ===

func scanRegistrationToken(row pgx.Row, lookupKey, lookupVal string) (*domain.RegistrationToken, error) {
	t, err := scanRegistrationTokenFields(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrNodeRegistrationTokenInvalid, "token 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan registration token").
			WithFields(lookupKey, lookupVal)
	}
	return t, nil
}

func scanRegistrationTokenRow(rows pgx.Rows) (*domain.RegistrationToken, error) {
	return scanRegistrationTokenFields(rows)
}

// nullableTime *time.Time → driver value；nil → NULL。
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func scanRegistrationTokenFields(s interface {
	Scan(dst ...any) error
}) (*domain.RegistrationToken, error) {
	t := &domain.RegistrationToken{}
	var (
		usedAt    *time.Time
		revokedAt *time.Time
	)
	if err := s.Scan(
		&t.ID, &t.TenantID, &t.Name, &t.TokenHash,
		&t.ExpiresAt, &usedAt, &revokedAt,
		&t.CreatedBy, &t.CreatedAt,
	); err != nil {
		return nil, err
	}
	t.UsedAt = usedAt
	t.RevokedAt = revokedAt
	return t, nil
}
