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

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// pgProjectRepo 用 pgxpool 实现 ProjectRepository。
type pgProjectRepo struct {
	pool *pgxpool.Pool
}

// NewProjectPG 构造 PG-backed ProjectRepository。
func NewProjectPG(pool *pgxpool.Pool) ProjectRepository {
	return &pgProjectRepo{pool: pool}
}

const selectProjectSQL = `
SELECT id::text,
       tenant_id::text,
       name,
       description,
       status,
       settings,
       stats_cache,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       archived_at,
       deleted_at
FROM projects
`

// === Insert ===

func (r *pgProjectRepo) Insert(ctx context.Context, p *domain.Project) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if err := p.ValidateForCreate(); err != nil {
		return err
	}

	settings := p.Settings
	if settings == nil {
		settings = map[string]any{}
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "tenancy.repo: marshal settings")
	}
	statsJSON, err := json.Marshal(p.StatsCache)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "tenancy.repo: marshal stats_cache")
	}

	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	if p.UpdatedAt.IsZero() {
		p.UpdatedAt = now
	}

	row := r.pool.QueryRow(ctx, `
		INSERT INTO projects (
			tenant_id, name, description, status,
			settings, stats_cache,
			created_by, created_at, updated_at
		) VALUES ($1::uuid, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9)
		RETURNING id::text
	`,
		p.TenantID, p.Name, p.Description, string(p.Status),
		string(settingsJSON), string(statsJSON),
		nullableUUID(p.CreatedBy),
		p.CreatedAt, p.UpdatedAt,
	)
	if err := row.Scan(&p.ID); err != nil {
		if isUniqueViolation(err, "projects_tenant_name_uniq") {
			return errx.New(errx.ErrProjectNameExists, "项目名在租户内已存在").
				WithFields("tenant_id", p.TenantID, "name", p.Name)
		}
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: insert project").
			WithFields("tenant_id", p.TenantID, "name", p.Name)
	}
	return nil
}

// === GetByID / List ===

func (r *pgProjectRepo) GetByID(ctx context.Context, id string) (*domain.Project, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx,
		selectProjectSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	return scanProject(row, "project_id", id)
}

func (r *pgProjectRepo) List(ctx context.Context, f ProjectFilter, p Page) ([]*domain.Project, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	if p.PageSize <= 0 {
		p.PageSize = 20
	}
	if p.Page < 1 {
		p.Page = 1
	}

	conds := []string{"deleted_at IS NULL"}
	args := []any{}
	if f.TenantID != "" {
		args = append(args, f.TenantID)
		conds = append(conds, "tenant_id = $"+strconv.Itoa(len(args))+"::uuid")
	}
	if f.Status != "" {
		args = append(args, string(f.Status))
		conds = append(conds, "status = $"+strconv.Itoa(len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+escapeLike(kw)+"%")
		conds = append(conds, "name ILIKE $"+strconv.Itoa(len(args)))
	}
	where := strings.Join(conds, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM projects WHERE `+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list projects count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	limitIdx := strconv.Itoa(len(args) - 1)
	offsetIdx := strconv.Itoa(len(args))
	rows, err := r.pool.Query(ctx,
		selectProjectSQL+`WHERE `+where+
			` ORDER BY created_at DESC LIMIT $`+limitIdx+` OFFSET $`+offsetIdx,
		args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list projects")
	}
	defer rows.Close()

	out := make([]*domain.Project, 0, p.PageSize)
	for rows.Next() {
		proj, err := scanProjectFields(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan project")
		}
		out = append(out, proj)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: list projects iter")
	}
	return out, total, nil
}

// === Archive / Unarchive / SoftDelete ===

func (r *pgProjectRepo) Archive(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE projects
		   SET status = 'archived',
		       archived_at = COALESCE(archived_at, now()),
		       updated_at = now()
		 WHERE id = $1::uuid AND deleted_at IS NULL
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: archive project").
			WithFields("project_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrProjectNotFound, "project 不存在").
			WithFields("project_id", id)
	}
	return nil
}

func (r *pgProjectRepo) Unarchive(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE projects
		   SET status = 'active',
		       archived_at = NULL,
		       updated_at = now()
		 WHERE id = $1::uuid AND deleted_at IS NULL
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: unarchive project").
			WithFields("project_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrProjectNotFound, "project 不存在").
			WithFields("project_id", id)
	}
	return nil
}

func (r *pgProjectRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "tenancy.repo: nil pool")
	}
	// 幂等：deleted_at 已非空 → noop（COALESCE 保留首次值）。仅当行不存在才返 NotFound。
	tag, err := r.pool.Exec(ctx, `
		UPDATE projects
		   SET deleted_at = COALESCE(deleted_at, now()),
		       updated_at = now()
		 WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: soft delete project").
			WithFields("project_id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrProjectNotFound, "project 不存在").
			WithFields("project_id", id)
	}
	return nil
}

// === scan helpers ===

func scanProject(row pgx.Row, lookupKey, lookupVal string) (*domain.Project, error) {
	p, err := scanProjectFields(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrProjectNotFound, "project 不存在").
			WithFields(lookupKey, lookupVal)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "tenancy.repo: scan project").
			WithFields(lookupKey, lookupVal)
	}
	return p, nil
}

func scanProjectFields(s interface {
	Scan(dst ...any) error
}) (*domain.Project, error) {
	p := &domain.Project{}
	var (
		status      string
		settingsRaw []byte
		statsRaw    []byte
		archivedAt  *time.Time
		deletedAt   *time.Time
	)
	if err := s.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &status,
		&settingsRaw, &statsRaw,
		&p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt, &archivedAt, &deletedAt,
	); err != nil {
		return nil, err
	}
	p.Status = domain.ProjectStatus(status)
	p.ArchivedAt = archivedAt
	p.DeletedAt = deletedAt
	if len(settingsRaw) > 0 {
		_ = json.Unmarshal(settingsRaw, &p.Settings)
	}
	if len(statsRaw) > 0 {
		_ = json.Unmarshal(statsRaw, &p.StatsCache)
	}
	return p, nil
}

func nullableUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
