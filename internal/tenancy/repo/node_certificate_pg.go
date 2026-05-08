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

// pgNodeCertRepo 用 pgxpool 实现 NodeCertificateRepository。
type pgNodeCertRepo struct {
	pool *pgxpool.Pool
}

// NewNodeCertificatePG 构造 PG-backed 实现。
func NewNodeCertificatePG(pool *pgxpool.Pool) NodeCertificateRepository {
	return &pgNodeCertRepo{pool: pool}
}

const selectNodeCertSQL = `
SELECT id::text,
       node_id::text,
       serial_number,
       fingerprint,
       common_name,
       cert_pem,
       issued_at,
       expires_at,
       revoked_at,
       COALESCE(issued_by_token::text, '') AS issued_by_token,
       created_at
FROM node_certificates
`

// === Insert ===

func (r *pgNodeCertRepo) Insert(ctx context.Context, c *domain.NodeCertificate) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := c.ValidateForCreate(); err != nil {
		return err
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = c.CreatedAt
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO node_certificates (
			node_id, serial_number, fingerprint, common_name, cert_pem,
			issued_at, expires_at, revoked_at, issued_by_token, created_at
		) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id::text
	`,
		c.NodeID, c.SerialNumber, c.Fingerprint, c.CommonName, c.CertPEM,
		c.IssuedAt, c.ExpiresAt, nullableTime(c.RevokedAt),
		nullableUUID(c.IssuedByToken), c.CreatedAt,
	)
	if err := row.Scan(&c.ID); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: insert node cert").
			WithFields("node_id", c.NodeID, "serial", c.SerialNumber)
	}
	return nil
}

// === GetBySerial / GetByFingerprint / ListByNode ===

func (r *pgNodeCertRepo) GetBySerial(ctx context.Context, serial string) (*domain.NodeCertificate, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectNodeCertSQL+`WHERE serial_number = $1`, serial)
	return scanNodeCert(row, "serial", serial)
}

func (r *pgNodeCertRepo) GetByFingerprint(ctx context.Context, fp string) (*domain.NodeCertificate, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectNodeCertSQL+`WHERE fingerprint = $1`, fp)
	return scanNodeCert(row, "fingerprint", "***")
}

func (r *pgNodeCertRepo) ListByNode(ctx context.Context, nodeID string) ([]*domain.NodeCertificate, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx,
		selectNodeCertSQL+`WHERE node_id = $1::uuid ORDER BY issued_at DESC`,
		nodeID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list node certs").
			WithFields("node_id", nodeID)
	}
	defer rows.Close()

	var out []*domain.NodeCertificate
	for rows.Next() {
		c, err := scanNodeCertRow(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan node cert")
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list node certs iter")
	}
	return out, nil
}

// === Revoke ===

func (r *pgNodeCertRepo) Revoke(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE node_certificates
		   SET revoked_at = COALESCE(revoked_at, now())
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: revoke node cert").
			WithFields("cert_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrNodeCertExpired, "证书不存在").
			WithFields("cert_id", id)
	}
	return nil
}

// === scan ===

func scanNodeCert(row pgx.Row, lookupKey, lookupVal string) (*domain.NodeCertificate, error) {
	c, err := scanNodeCertFields(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrNodeCertExpired, "证书无效或不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan node cert").
			WithFields(lookupKey, lookupVal)
	}
	return c, nil
}

func scanNodeCertRow(rows pgx.Rows) (*domain.NodeCertificate, error) {
	return scanNodeCertFields(rows)
}

func scanNodeCertFields(s interface {
	Scan(dst ...any) error
}) (*domain.NodeCertificate, error) {
	c := &domain.NodeCertificate{}
	var revokedAt *time.Time
	if err := s.Scan(
		&c.ID, &c.NodeID, &c.SerialNumber, &c.Fingerprint,
		&c.CommonName, &c.CertPEM,
		&c.IssuedAt, &c.ExpiresAt, &revokedAt,
		&c.IssuedByToken, &c.CreatedAt,
	); err != nil {
		return nil, err
	}
	c.RevokedAt = revokedAt
	return c, nil
}
