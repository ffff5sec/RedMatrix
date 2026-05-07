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

// pgMemberRepo 用 pgxpool 实现 ProjectMemberRepository。
type pgMemberRepo struct {
	pool *pgxpool.Pool
}

// NewProjectMemberPG 构造 PG-backed ProjectMemberRepository。
func NewProjectMemberPG(pool *pgxpool.Pool) ProjectMemberRepository {
	return &pgMemberRepo{pool: pool}
}

// === Add / Remove ===

func (r *pgMemberRepo) Add(ctx context.Context, m *domain.ProjectMember) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := m.ValidateForCreate(); err != nil {
		return err
	}
	if m.AddedAt.IsZero() {
		m.AddedAt = time.Now().UTC()
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO project_members (project_id, user_id, tenant_id, added_by, added_at)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5)
	`, m.ProjectID, m.UserID, m.TenantID, nullableUUID(m.AddedBy), m.AddedAt)
	if err != nil {
		// 复合主键冲突
		if isUniqueViolation(err, "project_members_pkey") {
			return errx.New(errx.ErrProjectMemberExists, "成员已存在").
				WithFields("project_id", m.ProjectID, "user_id", m.UserID)
		}
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: add member").
			WithFields("project_id", m.ProjectID, "user_id", m.UserID)
	}
	return nil
}

func (r *pgMemberRepo) Remove(ctx context.Context, projectID, userID string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM project_members
		 WHERE project_id = $1::uuid AND user_id = $2::uuid
	`, projectID, userID)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: remove member").
			WithFields("project_id", projectID, "user_id", userID)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrProjectMemberNotFound, "成员不存在").
			WithFields("project_id", projectID, "user_id", userID)
	}
	return nil
}

// === Exists / List ===

func (r *pgMemberRepo) Exists(ctx context.Context, projectID, userID string) (bool, error) {
	if r == nil || r.pool == nil {
		return false, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM project_members
			 WHERE project_id = $1::uuid AND user_id = $2::uuid
		)
	`, projectID, userID).Scan(&exists)
	if err != nil {
		return false, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: member exists").
			WithFields("project_id", projectID, "user_id", userID)
	}
	return exists, nil
}

func (r *pgMemberRepo) ListByProject(ctx context.Context, projectID string) ([]*domain.ProjectMember, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT project_id::text, user_id::text, tenant_id::text,
		       COALESCE(added_by::text, '') AS added_by,
		       added_at
		  FROM project_members
		 WHERE project_id = $1::uuid
		 ORDER BY added_at ASC
	`, projectID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list members").
			WithFields("project_id", projectID)
	}
	defer rows.Close()

	var out []*domain.ProjectMember
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan member").
				WithFields("project_id", projectID)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list members iter")
	}
	return out, nil
}

func (r *pgMemberRepo) ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT project_id::text
		  FROM project_members
		 WHERE user_id = $1::uuid
	`, userID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list user projects").
			WithFields("user_id", userID)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan project id")
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list user projects iter")
	}
	return out, nil
}

// === scan helpers ===

func scanMember(rows pgx.Rows) (*domain.ProjectMember, error) {
	m := &domain.ProjectMember{}
	if err := rows.Scan(&m.ProjectID, &m.UserID, &m.TenantID, &m.AddedBy, &m.AddedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errx.New(errx.ErrProjectMemberNotFound, "成员不存在")
		}
		return nil, err
	}
	return m, nil
}
