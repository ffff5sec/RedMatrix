package repo

import (
	"context"
	"errors"
	"strconv"
	"strings"
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

// List 列出 users 行，按 filter + page；返回 (rows, total, err)。
//
// total 是匹配 filter 的总数（不受 page/pagesize 影响）；caller 据此渲染分页 UI。
// 排序：created_at DESC（最新优先）。
func (r *pgRepo) List(ctx context.Context, filter ListFilter, page Page) ([]*domain.User, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if page.Page < 1 {
		page.Page = 1
	}
	if page.PageSize <= 0 {
		page.PageSize = 20
	}

	// 动态拼 WHERE：用占位符顺序与 args 对齐
	conds := []string{"1=1"}
	args := []any{}
	if filter.Status != "" {
		args = append(args, string(filter.Status))
		conds = append(conds, "status = $"+itoa(len(args)))
	}
	if filter.Role != "" {
		args = append(args, string(filter.Role))
		conds = append(conds, "role = $"+itoa(len(args)))
	}
	if kw := strings.TrimSpace(filter.Keyword); kw != "" {
		// ILIKE %kw%；保护 %_ 元字符
		args = append(args, "%"+escapeLike(kw)+"%")
		i := itoa(len(args))
		conds = append(conds,
			"(username ILIKE $"+i+" OR COALESCE(email,'') ILIKE $"+i+")")
	}
	where := strings.Join(conds, " AND ")

	// total
	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE `+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list users count")
	}

	// rows
	args = append(args, page.PageSize, (page.Page-1)*page.PageSize)
	limitIdx := itoa(len(args) - 1)
	offsetIdx := itoa(len(args))
	rows, err := r.pool.Query(ctx,
		selectUserSQL+` WHERE `+where+
			` ORDER BY created_at DESC LIMIT $`+limitIdx+` OFFSET $`+offsetIdx,
		args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list users")
	}
	defer rows.Close()

	out := make([]*domain.User, 0, page.PageSize)
	for rows.Next() {
		u := &domain.User{}
		var role, status string
		var lastLogin *time.Time
		if err := rows.Scan(
			&u.ID, &u.TenantID, &u.Username, &u.PasswordHash,
			&u.Email, &role, &status, &u.TokenVersion, &u.MustChangePassword,
			&lastLogin, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan user list")
		}
		u.Role = domain.Role(role)
		u.Status = domain.Status(status)
		if lastLogin != nil {
			u.LastLoginAt = *lastLogin
		}
		// PasswordHash 不返给上层（service 层会按需用，否则清掉）
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list users iter")
	}
	return out, total, nil
}

// UpdateEmail 更新单条 users.email。空字串 = SET NULL；不动 token_version。
func (r *pgRepo) UpdateEmail(ctx context.Context, id, email string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE users SET email = $2, updated_at = now() WHERE id = $1::uuid
	`, id, nullableString(email))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update email").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrUserNotFound, "用户不存在").WithFields("id", id)
	}
	return nil
}

// itoa 简写 strconv.Itoa（List 内多次拼占位符）。
func itoa(n int) string { return strconv.Itoa(n) }

// escapeLike 转义 LIKE/ILIKE 元字符（% _ \）。
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// CountByRole 数 users 表中指定角色的行数。
func (r *pgRepo) CountByRole(ctx context.Context, role domain.Role) (int, error) {
	if r == nil || r.pool == nil {
		return 0, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if !role.Valid() {
		return 0, errx.New(errx.ErrInvalidInput, "role 不合法").
			WithFields("got", string(role))
	}
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE role = $1`,
		string(role)).Scan(&n)
	if err != nil {
		return 0, errx.Wrap(errx.ErrDatabase, err, "identity.repo: count by role").
			WithFields("role", string(role))
	}
	return n, nil
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
