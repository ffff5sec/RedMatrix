package repo

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/finding/domain"
)

// === Finding ===

type pgFindingRepo struct {
	pool *pgxpool.Pool
}

// NewFindingPG 构造 FindingRepository。
func NewFindingPG(pool *pgxpool.Pool) FindingRepository {
	return &pgFindingRepo{pool: pool}
}

const selectFindingSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       dedup_key,
       template_id,
       source_result_id::text,
       asset_id::text,
       severity,
       title,
       host,
       COALESCE(description, '') AS description,
       COALESCE(reference, '') AS reference,
       status,
       assignee_id::text,
       first_seen_at,
       last_seen_at,
       occurrence_count,
       created_at,
       updated_at,
       deleted_at
FROM findings
`

func (r *pgFindingRepo) Upsert(ctx context.Context, f *domain.Finding) (*domain.Finding, bool, error) {
	if r == nil || r.pool == nil {
		return nil, false, errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	if err := f.ValidateForCreate(); err != nil {
		return nil, false, err
	}

	// 先尝试 INSERT；冲突 → UPDATE last_seen + count。
	// 用 ON CONFLICT (tenant_id, project_id, dedup_key) WHERE deleted_at IS NULL
	// 但 partial-unique-index 不能直接做 ON CONFLICT 目标，需要 ON CONFLICT (column) WHERE pred 形式。
	row := r.pool.QueryRow(ctx, `
		INSERT INTO findings (
			tenant_id, project_id, dedup_key, template_id, source_result_id, asset_id,
			severity, title, host, description, reference, status, assignee_id
		) VALUES (
			$1::uuid, $2::uuid, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (tenant_id, project_id, dedup_key) WHERE deleted_at IS NULL
		DO UPDATE SET
			last_seen_at = now(),
			occurrence_count = findings.occurrence_count + 1,
			updated_at = now()
		RETURNING id::text, created_at, updated_at, first_seen_at, last_seen_at, occurrence_count,
		          (xmax = 0) AS inserted
	`,
		f.TenantID, f.ProjectID, f.DedupKey, f.TemplateID,
		nullableUUIDPtr(f.SourceResultID), nullableUUIDPtr(f.AssetID),
		string(f.Severity), f.Title, f.Host, f.Description, f.Reference,
		string(f.Status), nullableUUIDPtr(f.AssigneeID),
	)
	var inserted bool
	if err := row.Scan(
		&f.ID, &f.CreatedAt, &f.UpdatedAt,
		&f.FirstSeenAt, &f.LastSeenAt, &f.OccurrenceCount,
		&inserted,
	); err != nil {
		return nil, false, errx.Wrap(errx.ErrDatabase, err, "finding.repo: upsert").
			WithFields("tenant_id", f.TenantID, "dedup", f.DedupKey)
	}
	return f, inserted, nil
}

func (r *pgFindingRepo) GetByID(ctx context.Context, id string) (*domain.Finding, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectFindingSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	f, err := scanFinding(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "finding.repo: get").WithFields("id", id)
	}
	return f, nil
}

func (r *pgFindingRepo) List(ctx context.Context, f FindingFilter, p Page) ([]*domain.Finding, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "finding.repo: nil pool")
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
	if strings.TrimSpace(f.ProjectID) != "" {
		args = append(args, f.ProjectID)
		clauses = append(clauses, "project_id = $"+itoa(len(args))+"::uuid")
	}
	if len(f.ProjectIDs) > 0 {
		args = append(args, f.ProjectIDs)
		clauses = append(clauses, "project_id = ANY($"+itoa(len(args))+"::uuid[])")
	}
	if strings.TrimSpace(f.Status) != "" {
		args = append(args, f.Status)
		clauses = append(clauses, "status = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.Severity) != "" {
		args = append(args, f.Severity)
		clauses = append(clauses, "severity = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.AssigneeID) != "" {
		args = append(args, f.AssigneeID)
		clauses = append(clauses, "assignee_id = $"+itoa(len(args))+"::uuid")
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+kw+"%")
		clauses = append(clauses, "(title ILIKE $"+itoa(len(args))+" OR host ILIKE $"+itoa(len(args))+")")
	}
	if minSev := strings.TrimSpace(f.MinSeverity); minSev != "" {
		// 用 CASE 表达式比较 rank
		args = append(args, minSev)
		clauses = append(clauses, severityRankSQL("severity")+" >= "+severityRankSQL("$"+itoa(len(args))))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM findings `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "finding.repo: list count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectFindingSQL + where + ` ORDER BY last_seen_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "finding.repo: list query")
	}
	defer rows.Close()
	out := []*domain.Finding{}
	for rows.Next() {
		one, err := scanFinding(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "finding.repo: list scan")
		}
		out = append(out, one)
	}
	return out, total, rows.Err()
}

// severityRankSQL 把 severity 字符串映射成数字 rank，用于 SQL 比较。
// 与 domain.Severity.Rank() 保持一致。
func severityRankSQL(col string) string {
	return `(CASE ` + col + `
		WHEN 'info' THEN 1
		WHEN 'low' THEN 2
		WHEN 'medium' THEN 3
		WHEN 'high' THEN 4
		WHEN 'critical' THEN 5
		ELSE 0 END)`
}

func (r *pgFindingRepo) UpdateStatus(ctx context.Context, id string, status domain.FindingStatus) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE findings SET status = $2, updated_at = now()
		WHERE id = $1::uuid AND deleted_at IS NULL
	`, id, string(status))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "finding.repo: update status").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgFindingRepo) UpdateAssignee(ctx context.Context, id string, assigneeID *string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE findings SET assignee_id = $2, updated_at = now()
		WHERE id = $1::uuid AND deleted_at IS NULL
	`, id, nullableUUIDPtr(assigneeID))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "finding.repo: update assignee").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgFindingRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE findings SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
		WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "finding.repo: soft delete").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
	}
	return nil
}

func scanFinding(s interface {
	Scan(dst ...any) error
}) (*domain.Finding, error) {
	out := &domain.Finding{}
	var srcResultID, assetID, assigneeID *string
	var severity, status string
	if err := s.Scan(
		&out.ID, &out.TenantID, &out.ProjectID, &out.DedupKey, &out.TemplateID,
		&srcResultID, &assetID,
		&severity, &out.Title, &out.Host,
		&out.Description, &out.Reference,
		&status, &assigneeID,
		&out.FirstSeenAt, &out.LastSeenAt, &out.OccurrenceCount,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	); err != nil {
		return nil, err
	}
	out.Severity = domain.Severity(severity)
	out.Status = domain.FindingStatus(status)
	if srcResultID != nil && *srcResultID != "" {
		out.SourceResultID = srcResultID
	}
	if assetID != nil && *assetID != "" {
		out.AssetID = assetID
	}
	if assigneeID != nil && *assigneeID != "" {
		out.AssigneeID = assigneeID
	}
	return out, nil
}

// === Event ===

type pgEventRepo struct {
	pool *pgxpool.Pool
}

// NewEventPG 构造 EventRepository。
func NewEventPG(pool *pgxpool.Pool) EventRepository {
	return &pgEventRepo{pool: pool}
}

const selectEventSQL = `
SELECT id::text,
       finding_id::text,
       actor_id::text,
       kind,
       from_status,
       to_status,
       from_assignee::text,
       to_assignee::text,
       COALESCE(body, '') AS body,
       created_at
FROM finding_events
`

func (r *pgEventRepo) Insert(ctx context.Context, e *domain.FindingEvent) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	if !e.Kind.Valid() {
		return errx.New(errx.ErrInvalidInput, "event.kind 不合法").
			WithFields("got", string(e.Kind))
	}
	var fromStatus, toStatus *string
	if e.FromStatus != nil {
		v := string(*e.FromStatus)
		fromStatus = &v
	}
	if e.ToStatus != nil {
		v := string(*e.ToStatus)
		toStatus = &v
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO finding_events (
			finding_id, actor_id, kind,
			from_status, to_status,
			from_assignee, to_assignee,
			body
		) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id::text, created_at
	`,
		e.FindingID, nullableUUIDPtr(e.ActorID), string(e.Kind),
		fromStatus, toStatus,
		nullableUUIDPtr(e.FromAssignee), nullableUUIDPtr(e.ToAssignee),
		e.Body,
	)
	if err := row.Scan(&e.ID, &e.CreatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "finding.repo: insert event").
			WithFields("finding_id", e.FindingID, "kind", string(e.Kind))
	}
	return nil
}

func (r *pgEventRepo) ListByFinding(ctx context.Context, findingID string) ([]*domain.FindingEvent, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "finding.repo: nil pool")
	}
	rows, err := r.pool.Query(ctx, selectEventSQL+`WHERE finding_id = $1::uuid ORDER BY created_at DESC LIMIT 500`, findingID)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "finding.repo: list events").WithFields("id", findingID)
	}
	defer rows.Close()
	out := []*domain.FindingEvent{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "finding.repo: scan event")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func scanEvent(s interface {
	Scan(dst ...any) error
}) (*domain.FindingEvent, error) {
	out := &domain.FindingEvent{}
	var actorID, fromAssignee, toAssignee *string
	var fromStatus, toStatus *string
	var kind string
	if err := s.Scan(
		&out.ID, &out.FindingID, &actorID, &kind,
		&fromStatus, &toStatus,
		&fromAssignee, &toAssignee,
		&out.Body, &out.CreatedAt,
	); err != nil {
		return nil, err
	}
	out.Kind = domain.FindingEventKind(kind)
	if actorID != nil && *actorID != "" {
		out.ActorID = actorID
	}
	if fromStatus != nil && *fromStatus != "" {
		fs := domain.FindingStatus(*fromStatus)
		out.FromStatus = &fs
	}
	if toStatus != nil && *toStatus != "" {
		ts := domain.FindingStatus(*toStatus)
		out.ToStatus = &ts
	}
	if fromAssignee != nil && *fromAssignee != "" {
		out.FromAssignee = fromAssignee
	}
	if toAssignee != nil && *toAssignee != "" {
		out.ToAssignee = toAssignee
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

func itoa(n int) string { return strconv.Itoa(n) }
