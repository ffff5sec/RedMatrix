package repo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// pgAPIKeyRepo 用 pgxpool 实现 APIKeyRepository。
type pgAPIKeyRepo struct {
	pool *pgxpool.Pool
}

// NewAPIKeyPG 构造 PG-backed APIKeyRepository。
func NewAPIKeyPG(pool *pgxpool.Pool) APIKeyRepository {
	return &pgAPIKeyRepo{pool: pool}
}

// selectAPIKeySQL 列序与 scanAPIKey 必须保持一致。
const selectAPIKeySQL = `
SELECT id::text,
       COALESCE(tenant_id::text, '')   AS tenant_id,
       user_id::text,
       name,
       key_prefix,
       secret_hash,
       scopes,
       expires_at,
       last_used_at,
       revoked_at,
       created_at
FROM api_keys
`

// === Insert ===

func (r *pgAPIKeyRepo) Insert(ctx context.Context, k *domain.APIKey) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if err := k.ValidateForCreate(); err != nil {
		return err
	}

	scopes := k.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "identity.repo: marshal scopes")
	}

	now := time.Now().UTC()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}

	row := r.pool.QueryRow(ctx, `
		INSERT INTO api_keys (
			tenant_id, user_id, name, key_prefix, secret_hash, scopes,
			expires_at, last_used_at, revoked_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10)
		RETURNING id::text, created_at
	`,
		nullableUUID(k.TenantID),
		k.UserID,
		k.Name,
		k.KeyPrefix,
		k.SecretHash,
		string(scopesJSON),
		nullableTime(k.ExpiresAt),
		nullableTime(k.LastUsedAt),
		nullableTime(k.RevokedAt),
		k.CreatedAt,
	)
	if err := row.Scan(&k.ID, &k.CreatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: insert api_key").
			WithFields("user_id", k.UserID, "key_prefix", k.KeyPrefix)
	}
	return nil
}

// === GetByID / FindByPrefix / ListByUser ===

func (r *pgAPIKeyRepo) GetByID(ctx context.Context, id string) (*domain.APIKey, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectAPIKeySQL+`WHERE id = $1`, id)
	return scanAPIKey(row, "api_key_id", id)
}

func (r *pgAPIKeyRepo) FindByPrefix(ctx context.Context, prefix string) (*domain.APIKey, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectAPIKeySQL+`WHERE key_prefix = $1`, prefix)
	return scanAPIKey(row, "key_prefix", prefix)
}

func (r *pgAPIKeyRepo) ListByUser(ctx context.Context, userID string) ([]*domain.APIKey, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectAPIKeySQL+`WHERE user_id = $1 ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list api_keys").
			WithFields("user_id", userID)
	}
	defer rows.Close()

	var out []*domain.APIKey
	for rows.Next() {
		k, err := scanAPIKeyRow(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan api_key").
				WithFields("user_id", userID)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list api_keys iter")
	}
	return out, nil
}

// === Revoke / UpdateLastUsed ===

// Revoke 设置 revoked_at=now()；幂等：已撤销的再调一遍 SQL UPDATE 仍命中行（不变更值），
// 不返 NotFound。仅当行真不存在时才返 ErrAPIKeyNotFound。
func (r *pgAPIKeyRepo) Revoke(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE api_keys
		   SET revoked_at = COALESCE(revoked_at, now())
		 WHERE id = $1
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: revoke api_key").
			WithFields("api_key_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrAPIKeyNotFound, "api_key 不存在").
			WithFields("api_key_id", id)
	}
	return nil
}

func (r *pgAPIKeyRepo) UpdateLastUsed(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE api_keys SET last_used_at = now() WHERE id = $1
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update last_used").
			WithFields("api_key_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrAPIKeyNotFound, "api_key 不存在").
			WithFields("api_key_id", id)
	}
	return nil
}

// === scan helpers ===

// scanAPIKey 单行 scan。pgx.ErrNoRows → ErrAPIKeyNotFound（带定位字段）。
func scanAPIKey(row pgx.Row, lookupKey, lookupVal string) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	var (
		scopesRaw  []byte
		expiresAt  *time.Time
		lastUsedAt *time.Time
		revokedAt  *time.Time
	)
	err := row.Scan(
		&k.ID, &k.TenantID, &k.UserID, &k.Name,
		&k.KeyPrefix, &k.SecretHash, &scopesRaw,
		&expiresAt, &lastUsedAt, &revokedAt, &k.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrAPIKeyNotFound, "api_key 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan api_key").
			WithFields(lookupKey, lookupVal)
	}
	return finishScan(k, scopesRaw, expiresAt, lastUsedAt, revokedAt)
}

// scanAPIKeyRow 多行 scan 时单行处理（返 raw err，由调用方包装）。
func scanAPIKeyRow(rows pgx.Rows) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	var (
		scopesRaw  []byte
		expiresAt  *time.Time
		lastUsedAt *time.Time
		revokedAt  *time.Time
	)
	if err := rows.Scan(
		&k.ID, &k.TenantID, &k.UserID, &k.Name,
		&k.KeyPrefix, &k.SecretHash, &scopesRaw,
		&expiresAt, &lastUsedAt, &revokedAt, &k.CreatedAt,
	); err != nil {
		return nil, err
	}
	return finishScan(k, scopesRaw, expiresAt, lastUsedAt, revokedAt)
}

func finishScan(
	k *domain.APIKey,
	scopesRaw []byte,
	expiresAt, lastUsedAt, revokedAt *time.Time,
) (*domain.APIKey, error) {
	if len(scopesRaw) > 0 {
		if err := json.Unmarshal(scopesRaw, &k.Scopes); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: unmarshal scopes").
				WithFields("api_key_id", k.ID)
		}
	}
	k.ExpiresAt = expiresAt
	k.LastUsedAt = lastUsedAt
	k.RevokedAt = revokedAt
	return k, nil
}

// nullableTime *time.Time 转可入 PG 的 driver value；nil → NULL。
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
