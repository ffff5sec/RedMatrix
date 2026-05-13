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

	"github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

type pgRepo struct {
	pool *pgxpool.Pool
}

// NewPG 构造 Repository PG 实现。
func NewPG(pool *pgxpool.Pool) Repository {
	return &pgRepo{pool: pool}
}

const selectSQL = `
SELECT id::text,
       actor_user_id::text,
       COALESCE(actor_username, '') AS actor_username,
       COALESCE(actor_ip, '') AS actor_ip,
       COALESCE(user_agent, '') AS user_agent,
       action,
       resource_kind,
       COALESCE(resource_id, '') AS resource_id,
       tenant_id::text,
       project_id::text,
       payload,
       prev_hash,
       hash,
       created_at
FROM audit_logs
`

func (r *pgRepo) Insert(ctx context.Context, a *domain.AuditLog) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "audit.repo: nil pool")
	}
	if err := a.ValidateForCreate(); err != nil {
		return err
	}
	payloadJSON, err := json.Marshal(a.Payload)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "audit: marshal payload")
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO audit_logs (
			actor_user_id, actor_username, actor_ip, user_agent,
			action, resource_kind, resource_id,
			tenant_id, project_id, payload,
			prev_hash, hash, created_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8::uuid, $9, $10,
			$11, $12, $13
		)
		RETURNING id::text
	`,
		nullableUUIDPtr(a.ActorUserID), a.ActorUsername, nullableString(a.ActorIP), nullableString(a.UserAgent),
		string(a.Action), a.ResourceKind, nullableString(a.ResourceID),
		a.TenantID, nullableUUIDPtr(a.ProjectID), payloadJSON,
		a.PrevHash, a.Hash, a.CreatedAt,
	)
	if err := row.Scan(&a.ID); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "audit: insert").
			WithFields("action", string(a.Action), "tenant_id", a.TenantID)
	}
	return nil
}

func (r *pgRepo) GetByID(ctx context.Context, id string) (*domain.AuditLog, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "audit.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectSQL+`WHERE id = $1::uuid`, id)
	a, err := scanLog(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrAuditLogNotFound, "audit 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "audit: get").WithFields("id", id)
	}
	return a, nil
}

func (r *pgRepo) LatestHash(ctx context.Context, tenantID string) (string, bool, error) {
	if r == nil || r.pool == nil {
		return "", false, errx.New(errx.ErrInternal, "audit.repo: nil pool")
	}
	var hash string
	err := r.pool.QueryRow(ctx, `
		SELECT hash FROM audit_logs
		WHERE tenant_id = $1::uuid
		ORDER BY created_at DESC
		LIMIT 1
	`, tenantID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GenesisPrevHash, false, nil
	}
	if err != nil {
		return "", false, errx.Wrap(errx.ErrDatabase, err, "audit: latest hash")
	}
	return hash, true, nil
}

func (r *pgRepo) List(ctx context.Context, f LogFilter, p Page) ([]*domain.AuditLog, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "audit.repo: nil pool")
	}
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 || p.PageSize > 200 {
		p.PageSize = 50
	}

	clauses := []string{"1=1"}
	args := []any{}
	if strings.TrimSpace(f.TenantID) != "" {
		args = append(args, f.TenantID)
		clauses = append(clauses, "tenant_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(f.ProjectID) != "" {
		args = append(args, f.ProjectID)
		clauses = append(clauses, "project_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(f.ActorUserID) != "" {
		args = append(args, f.ActorUserID)
		clauses = append(clauses, "actor_user_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(f.Action) != "" {
		args = append(args, f.Action)
		clauses = append(clauses, "action = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.ResourceKind) != "" {
		args = append(args, f.ResourceKind)
		clauses = append(clauses, "resource_kind = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.ResourceID) != "" {
		args = append(args, f.ResourceID)
		clauses = append(clauses, "resource_id = $"+itoa(len(args)))
	}
	if f.TimeFrom != nil {
		args = append(args, *f.TimeFrom)
		clauses = append(clauses, "created_at >= $"+itoa(len(args)))
	}
	if f.TimeTo != nil {
		args = append(args, *f.TimeTo)
		clauses = append(clauses, "created_at <= $"+itoa(len(args)))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM audit_logs `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "audit: list count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "audit: list query")
	}
	defer rows.Close()
	out := []*domain.AuditLog{}
	for rows.Next() {
		one, err := scanLog(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "audit: list scan")
		}
		out = append(out, one)
	}
	return out, total, rows.Err()
}

func (r *pgRepo) ListSegmentASC(ctx context.Context, tenantID string, from, to time.Time, limit int) ([]*domain.AuditLog, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "audit.repo: nil pool")
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, selectSQL+`
		WHERE tenant_id = $1::uuid
		  AND created_at >= $2
		  AND created_at <= $3
		ORDER BY created_at ASC
		LIMIT $4
	`, tenantID, from, to, limit)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "audit: list segment")
	}
	defer rows.Close()
	out := []*domain.AuditLog{}
	for rows.Next() {
		one, err := scanLog(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "audit: list segment scan")
		}
		out = append(out, one)
	}
	return out, rows.Err()
}

func scanLog(s interface {
	Scan(dst ...any) error
}) (*domain.AuditLog, error) {
	out := &domain.AuditLog{}
	var actorUserID, projectID *string
	var payloadBytes []byte
	var action string
	if err := s.Scan(
		&out.ID, &actorUserID, &out.ActorUsername, &out.ActorIP, &out.UserAgent,
		&action, &out.ResourceKind, &out.ResourceID,
		&out.TenantID, &projectID,
		&payloadBytes,
		&out.PrevHash, &out.Hash,
		&out.CreatedAt,
	); err != nil {
		return nil, err
	}
	out.Action = domain.ActionKind(action)
	if actorUserID != nil && *actorUserID != "" {
		out.ActorUserID = actorUserID
	}
	if projectID != nil && *projectID != "" {
		out.ProjectID = projectID
	}
	out.Payload = map[string]any{}
	if len(payloadBytes) > 0 {
		_ = json.Unmarshal(payloadBytes, &out.Payload)
	}
	return out, nil
}

// === helpers ===

func nullableUUIDPtr(p *string) any {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return *p
}

func nullableString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func itoa(n int) string { return strconv.Itoa(n) }
