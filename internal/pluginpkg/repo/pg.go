package repo

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// === PluginPackage ===

type pgPluginRepo struct {
	pool *pgxpool.Pool
}

// NewPluginPG 构造 PluginRepository。
func NewPluginPG(pool *pgxpool.Pool) PluginRepository {
	return &pgPluginRepo{pool: pool}
}

const selectPluginSQL = `
SELECT id::text,
       slug,
       version,
       platform,
       artifact_key,
       sha256,
       signature,
       signing_key_id,
       size_bytes,
       COALESCE(description, '') AS description,
       is_active,
       COALESCE(uploaded_by::text, '') AS uploaded_by,
       uploaded_at,
       deprecated_at
FROM plugin_packages
`

func (r *pgPluginRepo) Insert(ctx context.Context, p *domain.PluginPackage) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	if err := p.ValidateForCreate(); err != nil {
		return err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO plugin_packages (
			slug, version, platform, artifact_key, sha256, signature, signing_key_id,
			size_bytes, description, is_active, uploaded_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id::text, uploaded_at
	`,
		p.Slug, p.Version, string(p.Platform), p.ArtifactKey, p.SHA256, p.Signature, p.SigningKeyID,
		p.SizeBytes, p.Description, p.IsActive, nullableUUID(p.UploadedBy),
	)
	if err := row.Scan(&p.ID, &p.UploadedAt); err != nil {
		if isUniqueViolation(err) {
			return errx.New(errx.ErrPluginSlugVersionExists,
				"插件版本已存在").
				WithFields("slug", p.Slug, "version", p.Version, "platform", string(p.Platform))
		}
		return errx.Wrap(errx.ErrDatabase, err, "plugin.repo: insert").
			WithFields("slug", p.Slug, "version", p.Version)
	}
	return nil
}

func (r *pgPluginRepo) GetByID(ctx context.Context, id string) (*domain.PluginPackage, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectPluginSQL+`WHERE id = $1::uuid`, id)
	p, err := scanPlugin(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrPluginNotFound, "plugin 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: get").WithFields("id", id)
	}
	return p, nil
}

func (r *pgPluginRepo) List(ctx context.Context, f PluginFilter, p Page) ([]*domain.PluginPackage, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 || p.PageSize > 200 {
		p.PageSize = 50
	}

	clauses := []string{"1=1"}
	args := []any{}
	if strings.TrimSpace(f.Slug) != "" {
		args = append(args, f.Slug)
		clauses = append(clauses, "slug = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.Platform) != "" {
		args = append(args, f.Platform)
		clauses = append(clauses, "platform = $"+itoa(len(args)))
	}
	if f.Active != nil {
		args = append(args, *f.Active)
		clauses = append(clauses, "is_active = $"+itoa(len(args)))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM plugin_packages `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: list count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectPluginSQL + where + ` ORDER BY uploaded_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: list query")
	}
	defer rows.Close()
	out := []*domain.PluginPackage{}
	for rows.Next() {
		one, err := scanPlugin(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: list scan")
		}
		out = append(out, one)
	}
	return out, total, rows.Err()
}

func (r *pgPluginRepo) GetLatestActive(ctx context.Context, slug, platform string) (*domain.PluginPackage, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectPluginSQL+`
		WHERE slug = $1 AND platform = $2
		  AND is_active = TRUE
		  AND deprecated_at IS NULL
		ORDER BY uploaded_at DESC
		LIMIT 1
	`, slug, platform)
	p, err := scanPlugin(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrPluginNotFound, "无可用插件版本").
			WithFields("slug", slug, "platform", platform)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: get latest")
	}
	return p, nil
}

func (r *pgPluginRepo) UpdateActive(ctx context.Context, id string, isActive bool) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE plugin_packages SET is_active = $2
		WHERE id = $1::uuid AND deprecated_at IS NULL
	`, id, isActive)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "plugin.repo: update active").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrPluginNotFound, "plugin 不存在或已 deprecated").WithFields("id", id)
	}
	return nil
}

func (r *pgPluginRepo) Deprecate(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE plugin_packages
		   SET deprecated_at = COALESCE(deprecated_at, now()),
		       is_active = FALSE
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "plugin.repo: deprecate").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrPluginNotFound, "plugin 不存在").WithFields("id", id)
	}
	return nil
}

func scanPlugin(s interface {
	Scan(dst ...any) error
}) (*domain.PluginPackage, error) {
	out := &domain.PluginPackage{}
	var platform string
	if err := s.Scan(
		&out.ID, &out.Slug, &out.Version, &platform,
		&out.ArtifactKey, &out.SHA256, &out.Signature, &out.SigningKeyID,
		&out.SizeBytes, &out.Description, &out.IsActive,
		&out.UploadedBy,
		&out.UploadedAt, &out.DeprecatedAt,
	); err != nil {
		return nil, err
	}
	out.Platform = domain.Platform(platform)
	return out, nil
}

// === SigningKey ===

type pgSigningKeyRepo struct {
	pool *pgxpool.Pool
}

// NewSigningKeyPG 构造 SigningKeyRepository。
func NewSigningKeyPG(pool *pgxpool.Pool) SigningKeyRepository {
	return &pgSigningKeyRepo{pool: pool}
}

const selectKeySQL = `
SELECT id::text,
       key_id,
       public_key,
       COALESCE(description, '') AS description,
       created_at,
       revoked_at
FROM plugin_signing_keys
`

func (r *pgSigningKeyRepo) Insert(ctx context.Context, k *domain.SigningKey) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	if err := k.ValidateForCreate(); err != nil {
		return err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO plugin_signing_keys (key_id, public_key, description)
		VALUES ($1, $2, $3)
		RETURNING id::text, created_at
	`, k.KeyID, k.PublicKey, k.Description)
	if err := row.Scan(&k.ID, &k.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			// 同 key_id 已存在 → 当成幂等
			existing, gerr := r.GetByKeyID(ctx, k.KeyID)
			if gerr == nil {
				*k = *existing
				return nil
			}
		}
		return errx.Wrap(errx.ErrDatabase, err, "plugin.repo: insert key").WithFields("key_id", k.KeyID)
	}
	return nil
}

func (r *pgSigningKeyRepo) GetByKeyID(ctx context.Context, keyID string) (*domain.SigningKey, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectKeySQL+`WHERE key_id = $1`, keyID)
	k, err := scanKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrPluginNotFound, "signing_key 不存在").WithFields("key_id", keyID)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: get key")
	}
	return k, nil
}

func (r *pgSigningKeyRepo) ListActive(ctx context.Context) ([]*domain.SigningKey, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, selectKeySQL+`WHERE revoked_at IS NULL ORDER BY created_at DESC`)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: list keys")
	}
	defer rows.Close()
	out := []*domain.SigningKey{}
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "plugin.repo: scan key")
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (r *pgSigningKeyRepo) Revoke(ctx context.Context, keyID string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "plugin.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE plugin_signing_keys
		   SET revoked_at = COALESCE(revoked_at, now())
		 WHERE key_id = $1
	`, keyID)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "plugin.repo: revoke key")
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrPluginNotFound, "signing_key 不存在").WithFields("key_id", keyID)
	}
	return nil
}

func scanKey(s interface {
	Scan(dst ...any) error
}) (*domain.SigningKey, error) {
	out := &domain.SigningKey{}
	if err := s.Scan(
		&out.ID, &out.KeyID, &out.PublicKey, &out.Description,
		&out.CreatedAt, &out.RevokedAt,
	); err != nil {
		return nil, err
	}
	return out, nil
}

// === helpers ===

func nullableUUID(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func itoa(n int) string { return strconv.Itoa(n) }

// isUniqueViolation pgx error 23505。
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "23505") ||
		strings.Contains(err.Error(), "duplicate key value")
}
