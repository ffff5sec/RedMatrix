package repo

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// pgRepo 用 pgxpool 实现 Repository。
type pgRepo struct {
	pool *pgxpool.Pool
}

// NewPG 构造 PG-backed Repository。pool 通常是 redmatrix_app 池（受 RLS 约束；
// LLD 22-rls §4.4）。SuperAdmin 跨租户场景由 service 层切到 maintenance pool。
func NewPG(pool *pgxpool.Pool) Repository {
	return &pgRepo{pool: pool}
}

// === Create ===

func (r *pgRepo) Create(ctx context.Context, u *domain.User) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if err := u.ValidateForCreate(); err != nil {
		return err
	}

	now := time.Now().UTC()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}

	row := r.pool.QueryRow(ctx, `
		INSERT INTO users (
			tenant_id, username, password_hash, email, role, status,
			token_version, must_change_password, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id::text
	`,
		nullableUUID(u.TenantID),
		u.Username,
		u.PasswordHash,
		nullableString(u.Email),
		string(u.Role),
		string(u.Status),
		u.TokenVersion,
		u.MustChangePassword,
		u.CreatedAt,
		u.UpdatedAt,
	)
	if err := row.Scan(&u.ID); err != nil {
		if isUniqueViolation(err, "users_username_uniq") {
			return errx.New(errx.ErrUserUsernameExists,
				"用户名已存在").WithFields("username", u.Username)
		}
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: create user").
			WithFields("username", u.Username)
	}
	return nil
}

// === GetByID / GetByUsername ===

func (r *pgRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectUserSQL+` WHERE id = $1::uuid`, id)
	return scanUser(row, "id", id)
}

func (r *pgRepo) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectUserSQL+` WHERE username = $1`, username)
	return scanUser(row, "username", username)
}

// === Update* ===

func (r *pgRepo) UpdatePassword(ctx context.Context, id, newHash string, mustChange bool) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE users
		   SET password_hash = $2,
		       must_change_password = $3,
		       token_version = token_version + 1,
		       updated_at = now()
		 WHERE id = $1::uuid
	`, id, newHash, mustChange)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update password").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgRepo) UpdateLastLogin(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET last_login_at = now(), updated_at = now()
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update last_login").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgRepo) IncrementTokenVersion(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET token_version = token_version + 1, updated_at = now()
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: bump token_version").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
	}
	return nil
}

// LogoutAllSessions 单事务跑两条 UPDATE：tv++ + 全部未过期 session 置 expires_at=now()。
// LLD 10 §5.5：tv 是吊销机制；sessions.expires_at 是 UI 同步（列表显示 inactive）。
func (r *pgRepo) LogoutAllSessions(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE users SET token_version = token_version + 1, updated_at = now()
			 WHERE id = $1::uuid
		`, id)
		if err != nil {
			return errx.Wrap(errx.ErrDatabase, err, "identity.repo: bump tv").
				WithFields("id", id)
		}
		if tag.RowsAffected() == 0 {
			return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE user_sessions SET expires_at = now()
			 WHERE user_id = $1::uuid AND expires_at > now()
		`, id); err != nil {
			return errx.Wrap(errx.ErrDatabase, err, "identity.repo: expire sessions").
				WithFields("user_id", id)
		}
		return nil
	})
}

func (r *pgRepo) UpdateStatus(ctx context.Context, id string, status domain.Status) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if !status.Valid() {
		return errx.New(errx.ErrInvalidInput, "status 不合法").
			WithFields("got", string(status))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET status = $2, updated_at = now()
		 WHERE id = $1::uuid
	`, id, string(status))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update status").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
	}
	return nil
}

// === Helpers ===

const selectUserSQL = `
	SELECT id::text,
	       COALESCE(tenant_id::text, '') AS tenant_id,
	       username,
	       password_hash,
	       COALESCE(email, '') AS email,
	       role,
	       status,
	       token_version,
	       must_change_password,
	       last_login_at,
	       created_at,
	       updated_at
	  FROM users
`

// scanUser 扫描 selectUserSQL 的 12 列到 *domain.User。
// pgx.ErrNoRows → ErrUserNotFound（带定位字段）。
func scanUser(row pgx.Row, lookupKey, lookupVal string) (*domain.User, error) {
	var (
		u         domain.User
		role      string
		status    string
		lastLogin *time.Time
	)
	err := row.Scan(
		&u.ID,
		&u.TenantID,
		&u.Username,
		&u.PasswordHash,
		&u.Email,
		&role,
		&status,
		&u.TokenVersion,
		&u.MustChangePassword,
		&lastLogin,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrUserNotFound, "用户不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan user").
			WithFields(lookupKey, lookupVal)
	}
	u.Role = domain.Role(role)
	u.Status = domain.Status(status)
	if lastLogin != nil {
		u.LastLoginAt = *lastLogin
	}
	return &u, nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// isUniqueViolation 判断 err 是否为 PG 唯一约束冲突。
// constraint 不为空时，进一步要求约束名匹配（区分 username 重复 vs 其他唯一约束）。
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
