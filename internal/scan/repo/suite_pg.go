package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// pgSuiteRepo —— pgxpool-backed SuiteRepository。
type pgSuiteRepo struct {
	pool *pgxpool.Pool
}

// NewSuitePG 构造 PG 实现。
func NewSuitePG(pool *pgxpool.Pool) SuiteRepository {
	return &pgSuiteRepo{pool: pool}
}

const selectSuiteSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       name,
       kinds,
       target_kind,
       default_settings,
       schedule_kind,
       COALESCE(cron_expr, '') AS cron_expr,
       default_targets,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       deleted_at
FROM scan_suites
`

func (r *pgSuiteRepo) Insert(ctx context.Context, s *domain.ScanSuite) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if err := s.ValidateForCreate(); err != nil {
		return err
	}
	settingsJSON, err := json.Marshal(s.DefaultSettings)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "marshal scan_suite.default_settings")
	}
	kinds := make([]string, 0, len(s.Kinds))
	for _, k := range s.Kinds {
		kinds = append(kinds, string(k))
	}
	defaultTargets := s.DefaultTargets
	if defaultTargets == nil {
		defaultTargets = []string{}
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO scan_suites (
			tenant_id, project_id, name, kinds, target_kind, default_settings,
			schedule_kind, cron_expr, default_targets,
			created_by
		) VALUES ($1::uuid, $2, $3, $4::text[], $5, $6, $7, $8, $9::text[], $10)
		RETURNING id::text, created_at, updated_at
	`,
		s.TenantID, nullableUUIDPtr(s.ProjectID), s.Name,
		kinds, string(s.TargetKind), settingsJSON,
		string(s.ScheduleKind), s.CronExpr, defaultTargets,
		nullableUUID(s.CreatedBy),
	)
	if err := row.Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: insert suite").
			WithFields("tenant_id", s.TenantID, "name", s.Name)
	}
	return nil
}

func (r *pgSuiteRepo) GetByID(ctx context.Context, id string) (*domain.ScanSuite, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectSuiteSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	s, err := scanSuite(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrTaskNotFound, "suite 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: get suite").WithFields("id", id)
	}
	return s, nil
}

func (r *pgSuiteRepo) List(ctx context.Context, f SuiteFilter, p Page) ([]*domain.ScanSuite, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if p.Page <= 0 {
		p.Page = 1
	}
	if p.PageSize <= 0 || p.PageSize > 200 {
		p.PageSize = 50
	}

	clauses := []string{"deleted_at IS NULL"}
	args := []any{}
	if strings.TrimSpace(f.TenantID) != "" {
		args = append(args, f.TenantID)
		clauses = append(clauses, "tenant_id = $"+itoa(len(args))+"::uuid")
	}
	if pid := strings.TrimSpace(f.ProjectID); pid != "" {
		// 含跨项目套件 (project_id IS NULL) + 该项目套件
		args = append(args, pid)
		clauses = append(clauses, "(project_id IS NULL OR project_id = $"+itoa(len(args))+"::uuid)")
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+kw+"%")
		clauses = append(clauses, "name ILIKE $"+itoa(len(args)))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM scan_suites `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectSuiteSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite query")
	}
	defer rows.Close()

	out := []*domain.ScanSuite{}
	for rows.Next() {
		s, err := scanSuite(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite scan")
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

func (r *pgSuiteRepo) ListCronTemplates(ctx context.Context) ([]SuiteCronTemplate, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, cron_expr
		FROM scan_suites
		WHERE schedule_kind = 'cron'
		  AND deleted_at IS NULL
		  AND length(trim(cron_expr)) > 0
	`)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite cron templates")
	}
	defer rows.Close()
	out := []SuiteCronTemplate{}
	for rows.Next() {
		var t SuiteCronTemplate
		if err := rows.Scan(&t.SuiteID, &t.CronExpr); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: scan suite cron")
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *pgSuiteRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_suites SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
		WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: soft delete suite").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "suite 不存在").WithFields("id", id)
	}
	return nil
}

func scanSuite(s interface {
	Scan(dst ...any) error
}) (*domain.ScanSuite, error) {
	out := &domain.ScanSuite{}
	var settingsBytes []byte
	var projectID *string
	var kinds []string
	var scheduleKind string
	if err := s.Scan(
		&out.ID, &out.TenantID, &projectID, &out.Name,
		&kinds, (*string)(&out.TargetKind),
		&settingsBytes,
		&scheduleKind, &out.CronExpr, &out.DefaultTargets,
		&out.CreatedBy,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	); err != nil {
		return nil, err
	}
	if projectID != nil && *projectID != "" {
		out.ProjectID = projectID
	}
	out.Kinds = make([]domain.TaskKind, 0, len(kinds))
	for _, k := range kinds {
		out.Kinds = append(out.Kinds, domain.TaskKind(k))
	}
	out.DefaultSettings = map[string]any{}
	if len(settingsBytes) > 0 {
		_ = json.Unmarshal(settingsBytes, &out.DefaultSettings)
	}
	out.ScheduleKind = domain.ScheduleKind(scheduleKind)
	return out, nil
}

// === scan_suite_runs ===

type pgSuiteRunRepo struct {
	pool *pgxpool.Pool
}

func NewSuiteRunPG(pool *pgxpool.Pool) SuiteRunRepository {
	return &pgSuiteRunRepo{pool: pool}
}

const selectSuiteRunSQL = `
SELECT id::text,
       suite_id::text,
       tenant_id::text,
       project_id::text,
       targets,
       status,
       current_step,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       finished_at
FROM scan_suite_runs
`

func (r *pgSuiteRunRepo) Insert(ctx context.Context, run *domain.ScanSuiteRun) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if err := run.ValidateForCreate(); err != nil {
		return err
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO scan_suite_runs (suite_id, tenant_id, project_id, targets, status, created_by)
		VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text[], $5, $6)
		RETURNING id::text, created_at, updated_at
	`,
		run.SuiteID, run.TenantID, run.ProjectID, run.Targets, string(run.Status),
		nullableUUID(run.CreatedBy),
	)
	if err := row.Scan(&run.ID, &run.CreatedAt, &run.UpdatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: insert suite run").
			WithFields("suite_id", run.SuiteID)
	}
	return nil
}

func (r *pgSuiteRunRepo) GetByID(ctx context.Context, id string) (*domain.ScanSuiteRun, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectSuiteRunSQL+`WHERE id = $1::uuid`, id)
	out, err := scanSuiteRun(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrTaskNotFound, "suite_run 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "scan.repo: get suite run").WithFields("id", id)
	}
	return out, nil
}

func (r *pgSuiteRunRepo) List(ctx context.Context, f SuiteRunFilter, p Page) ([]*domain.ScanSuiteRun, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "scan.repo: nil pool")
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
	if strings.TrimSpace(f.SuiteID) != "" {
		args = append(args, f.SuiteID)
		clauses = append(clauses, "suite_id = $"+itoa(len(args))+"::uuid")
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM scan_suite_runs `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite_runs count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectSuiteRunSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite_runs query")
	}
	defer rows.Close()
	out := []*domain.ScanSuiteRun{}
	for rows.Next() {
		one, err := scanSuiteRun(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "scan.repo: list suite_runs scan")
		}
		out = append(out, one)
	}
	return out, total, rows.Err()
}

func (r *pgSuiteRunRepo) UpdateCurrentStep(ctx context.Context, id string, step int) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if step < 0 {
		return errx.New(errx.ErrInvalidInput, "current_step 不能 < 0").WithFields("step", step)
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_suite_runs
		   SET current_step = $2,
		       updated_at = now()
		 WHERE id = $1::uuid
	`, id, step)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: update suite_run current_step").
			WithFields("id", id, "step", step)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "suite_run 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgSuiteRunRepo) UpdateStatus(ctx context.Context, id string, status domain.SuiteRunStatus, finished bool) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "scan.repo: nil pool")
	}
	if !status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "suite_run status 不合法").
			WithFields("got", string(status))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scan_suite_runs
		   SET status = $2,
		       finished_at = CASE WHEN $3::bool THEN now() ELSE finished_at END,
		       updated_at = now()
		 WHERE id = $1::uuid
	`, id, string(status), finished)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "scan.repo: update suite_run status").
			WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrTaskNotFound, "suite_run 不存在").WithFields("id", id)
	}
	return nil
}

func scanSuiteRun(s interface {
	Scan(dst ...any) error
}) (*domain.ScanSuiteRun, error) {
	out := &domain.ScanSuiteRun{}
	var status string
	if err := s.Scan(
		&out.ID, &out.SuiteID, &out.TenantID, &out.ProjectID,
		&out.Targets, &status, &out.CurrentStep,
		&out.CreatedBy,
		&out.CreatedAt, &out.UpdatedAt, &out.FinishedAt,
	); err != nil {
		return nil, err
	}
	out.Status = domain.SuiteRunStatus(status)
	return out, nil
}
