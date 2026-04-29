package repo

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// pgSessionRepo 用 pgxpool 实现 SessionRepository。
type pgSessionRepo struct {
	pool *pgxpool.Pool
}

// NewSessionPG 构造 PG-backed SessionRepository。
func NewSessionPG(pool *pgxpool.Pool) SessionRepository {
	return &pgSessionRepo{pool: pool}
}

// selectSessionSQL 列序与 scanSession 必须保持一致。
const selectSessionSQL = `
SELECT id::text,
       COALESCE(tenant_id::text, '')   AS tenant_id,
       user_id::text,
       user_agent,
       COALESCE(host(ip), '')          AS ip_text,
       issued_at,
       last_seen_at,
       token_version,
       expires_at
FROM user_sessions
`

// === Create ===

func (r *pgSessionRepo) Create(ctx context.Context, s *domain.Session) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	if err := s.ValidateForCreate(); err != nil {
		return err
	}

	row := r.pool.QueryRow(ctx, `
		INSERT INTO user_sessions (
			tenant_id, user_id, user_agent, ip,
			issued_at, last_seen_at, token_version, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id::text
	`,
		nullableUUID(s.TenantID),
		s.UserID,
		s.UserAgent,
		nullableInet(s.IP),
		s.IssuedAt,
		s.LastSeenAt,
		s.TokenVersion,
		s.ExpiresAt,
	)
	if err := row.Scan(&s.ID); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: create session").
			WithFields("user_id", s.UserID)
	}
	return nil
}

// === GetByID / ListByUser ===

func (r *pgSessionRepo) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectSessionSQL+`WHERE id = $1`, id)
	return scanSession(row, "session_id", id)
}

func (r *pgSessionRepo) ListByUser(ctx context.Context, userID string) ([]*domain.Session, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectSessionSQL+`WHERE user_id = $1 ORDER BY expires_at DESC`,
		userID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list sessions").
			WithFields("user_id", userID)
	}
	defer rows.Close()

	var out []*domain.Session
	for rows.Next() {
		s, err := scanSessionRow(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan session").
				WithFields("user_id", userID)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: list sessions iter")
	}
	return out, nil
}

// === Delete / ExpireAllByUser / UpdateLastSeen ===

func (r *pgSessionRepo) Delete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `DELETE FROM user_sessions WHERE id = $1`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: delete session").
			WithFields("session_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrSessionNotFound, "session 不存在").
			WithFields("session_id", id)
	}
	return nil
}

func (r *pgSessionRepo) ExpireAllByUser(ctx context.Context, userID string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	// 仅刷未过期的：避免无意义写老行
	_, err := r.pool.Exec(ctx, `
		UPDATE user_sessions
		   SET expires_at = now()
		 WHERE user_id = $1 AND expires_at > now()
	`, userID)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: expire sessions").
			WithFields("user_id", userID)
	}
	return nil
}

func (r *pgSessionRepo) UpdateLastSeen(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "identity.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE user_sessions SET last_seen_at = now() WHERE id = $1
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "identity.repo: update last_seen").
			WithFields("session_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrSessionNotFound, "session 不存在").
			WithFields("session_id", id)
	}
	return nil
}

// === scan helpers ===

// scanSession 单行 scan。pgx.ErrNoRows → ErrSessionNotFound（带定位字段）。
func scanSession(row pgx.Row, lookupKey, lookupVal string) (*domain.Session, error) {
	s := &domain.Session{}
	var ipText string
	err := row.Scan(
		&s.ID, &s.TenantID, &s.UserID, &s.UserAgent,
		&ipText, &s.IssuedAt, &s.LastSeenAt, &s.TokenVersion, &s.ExpiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrSessionNotFound, "session 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "identity.repo: scan session").
			WithFields(lookupKey, lookupVal)
	}
	if ipText != "" {
		if addr, perr := netip.ParseAddr(ipText); perr == nil {
			s.IP = addr
		}
	}
	return s, nil
}

// scanSessionRow 多行 scan 时单行处理（返回 raw err，由调用方包装）。
func scanSessionRow(rows pgx.Rows) (*domain.Session, error) {
	s := &domain.Session{}
	var ipText string
	if err := rows.Scan(
		&s.ID, &s.TenantID, &s.UserID, &s.UserAgent,
		&ipText, &s.IssuedAt, &s.LastSeenAt, &s.TokenVersion, &s.ExpiresAt,
	); err != nil {
		return nil, err
	}
	if ipText != "" {
		if addr, perr := netip.ParseAddr(ipText); perr == nil {
			s.IP = addr
		}
	}
	return s, nil
}

// nullableInet 将 netip.Addr 转成 PG 可识别值；零值（!IsValid）→ NULL。
func nullableInet(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a.String()
}
