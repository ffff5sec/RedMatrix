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
	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// === Subscription ===

type pgSubscriptionRepo struct {
	pool *pgxpool.Pool
}

// NewSubscriptionPG 构造 SubscriptionRepository PG 实现。
func NewSubscriptionPG(pool *pgxpool.Pool) SubscriptionRepository {
	return &pgSubscriptionRepo{pool: pool}
}

const selectSubSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       name,
       event_kinds,
       channel,
       config,
       filter,
       enabled,
       COALESCE(created_by::text, '') AS created_by,
       created_at,
       updated_at,
       deleted_at
FROM notification_subscriptions
`

func (r *pgSubscriptionRepo) Insert(ctx context.Context, s *domain.Subscription) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	if err := s.ValidateForCreate(); err != nil {
		return err
	}
	configJSON, err := json.Marshal(s.Config)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "marshal subscription.config")
	}
	filterJSON, err := json.Marshal(s.Filter)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "marshal subscription.filter")
	}
	kinds := make([]string, 0, len(s.EventKinds))
	for _, k := range s.EventKinds {
		kinds = append(kinds, string(k))
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO notification_subscriptions (
			tenant_id, project_id, name, event_kinds, channel, config, filter, enabled, created_by
		) VALUES ($1::uuid, $2, $3, $4::text[], $5, $6, $7, $8, $9)
		RETURNING id::text, created_at, updated_at
	`,
		s.TenantID, nullableUUIDPtr(s.ProjectID), s.Name,
		kinds, string(s.Channel), configJSON, filterJSON, s.Enabled,
		nullableUUID(s.CreatedBy),
	)
	if err := row.Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: insert subscription").
			WithFields("tenant_id", s.TenantID, "name", s.Name)
	}
	return nil
}

func (r *pgSubscriptionRepo) GetByID(ctx context.Context, id string) (*domain.Subscription, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectSubSQL+`WHERE id = $1::uuid AND deleted_at IS NULL`, id)
	s, err := scanSubscription(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "notify.repo: get subscription").WithFields("id", id)
	}
	return s, nil
}

func (r *pgSubscriptionRepo) List(ctx context.Context, f SubscriptionFilter, p Page) ([]*domain.Subscription, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "notify.repo: nil pool")
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
		args = append(args, pid)
		clauses = append(clauses, "(project_id IS NULL OR project_id = $"+itoa(len(args))+"::uuid)")
	}
	if ch := strings.TrimSpace(f.Channel); ch != "" {
		args = append(args, ch)
		clauses = append(clauses, "channel = $"+itoa(len(args)))
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		args = append(args, "%"+kw+"%")
		clauses = append(clauses, "name ILIKE $"+itoa(len(args)))
	}
	if f.Enabled != nil {
		args = append(args, *f.Enabled)
		clauses = append(clauses, "enabled = $"+itoa(len(args)))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM notification_subscriptions `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list subscription count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectSubSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list subscription query")
	}
	defer rows.Close()

	out := []*domain.Subscription{}
	for rows.Next() {
		s, err := scanSubscription(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list subscription scan")
		}
		out = append(out, s)
	}
	return out, total, rows.Err()
}

func (r *pgSubscriptionRepo) Update(ctx context.Context, s *domain.Subscription) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	if err := s.ValidateForCreate(); err != nil {
		return err
	}
	configJSON, _ := json.Marshal(s.Config)
	filterJSON, _ := json.Marshal(s.Filter)
	kinds := make([]string, 0, len(s.EventKinds))
	for _, k := range s.EventKinds {
		kinds = append(kinds, string(k))
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE notification_subscriptions
		   SET name = $2,
		       event_kinds = $3::text[],
		       channel = $4,
		       config = $5,
		       filter = $6,
		       enabled = $7,
		       updated_at = now()
		 WHERE id = $1::uuid AND deleted_at IS NULL
	`, s.ID, s.Name, kinds, string(s.Channel), configJSON, filterJSON, s.Enabled)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: update subscription").
			WithFields("id", s.ID)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", s.ID)
	}
	return nil
}

func (r *pgSubscriptionRepo) SoftDelete(ctx context.Context, id string) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE notification_subscriptions SET deleted_at = COALESCE(deleted_at, now()), updated_at = now()
		WHERE id = $1::uuid
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: soft delete subscription").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgSubscriptionRepo) ListMatching(
	ctx context.Context,
	tenantID string,
	projectID *string,
	eventKind domain.EventKind,
) ([]*domain.Subscription, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	// project_id NULL（tenant-wide）始终匹配；非空时还匹配项目级
	q := selectSubSQL + `
		WHERE deleted_at IS NULL
		  AND enabled = TRUE
		  AND tenant_id = $1::uuid
		  AND (project_id IS NULL OR project_id = $2::uuid)
		  AND $3 = ANY(event_kinds)
		ORDER BY created_at`
	var pidArg any
	if projectID == nil || *projectID == "" {
		// 当 event 无 project（如租户级），仅匹配 tenant-wide
		q = selectSubSQL + `
			WHERE deleted_at IS NULL
			  AND enabled = TRUE
			  AND tenant_id = $1::uuid
			  AND project_id IS NULL
			  AND $2 = ANY(event_kinds)
			ORDER BY created_at`
		rows, err := r.pool.Query(ctx, q, tenantID, string(eventKind))
		return scanSubsRows(rows, err)
	}
	pidArg = *projectID
	rows, err := r.pool.Query(ctx, q, tenantID, pidArg, string(eventKind))
	return scanSubsRows(rows, err)
}

func scanSubsRows(rows pgx.Rows, qerr error) ([]*domain.Subscription, error) {
	if qerr != nil {
		return nil, errx.Wrap(errx.ErrDatabase, qerr, "notify.repo: list matching")
	}
	defer rows.Close()
	out := []*domain.Subscription{}
	for rows.Next() {
		s, err := scanSubscription(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "notify.repo: scan matching")
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func scanSubscription(s interface {
	Scan(dst ...any) error
}) (*domain.Subscription, error) {
	out := &domain.Subscription{}
	var configBytes, filterBytes []byte
	var projectID *string
	var kinds []string
	var channel string
	if err := s.Scan(
		&out.ID, &out.TenantID, &projectID, &out.Name,
		&kinds, &channel,
		&configBytes, &filterBytes,
		&out.Enabled,
		&out.CreatedBy,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	); err != nil {
		return nil, err
	}
	if projectID != nil && *projectID != "" {
		out.ProjectID = projectID
	}
	out.Channel = domain.Channel(channel)
	out.EventKinds = make([]domain.EventKind, 0, len(kinds))
	for _, k := range kinds {
		out.EventKinds = append(out.EventKinds, domain.EventKind(k))
	}
	out.Config = map[string]any{}
	if len(configBytes) > 0 {
		_ = json.Unmarshal(configBytes, &out.Config)
	}
	out.Filter = map[string]any{}
	if len(filterBytes) > 0 {
		_ = json.Unmarshal(filterBytes, &out.Filter)
	}
	return out, nil
}

// === Delivery ===

type pgDeliveryRepo struct {
	pool *pgxpool.Pool
}

// NewDeliveryPG 构造 DeliveryRepository PG 实现。
func NewDeliveryPG(pool *pgxpool.Pool) DeliveryRepository {
	return &pgDeliveryRepo{pool: pool}
}

const selectDelSQL = `
SELECT id::text,
       subscription_id::text,
       tenant_id::text,
       project_id::text,
       event_kind,
       event_topic,
       payload,
       status,
       attempts,
       COALESCE(last_error, '') AS last_error,
       scheduled_at,
       created_at,
       sent_at
FROM notification_deliveries
`

func (r *pgDeliveryRepo) Insert(ctx context.Context, d *domain.Delivery) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	payloadJSON, err := json.Marshal(d.Payload)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "marshal delivery.payload")
	}
	if d.Status == "" {
		d.Status = domain.DeliveryPending
	}
	row := r.pool.QueryRow(ctx, `
		INSERT INTO notification_deliveries (
			subscription_id, tenant_id, project_id,
			event_kind, event_topic, payload, status, attempts, scheduled_at
		) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id::text, created_at
	`,
		d.SubscriptionID, d.TenantID, nullableUUIDPtr(d.ProjectID),
		string(d.EventKind), d.EventTopic, payloadJSON,
		string(d.Status), d.Attempts, d.ScheduledAt,
	)
	if err := row.Scan(&d.ID, &d.CreatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: insert delivery").
			WithFields("subscription_id", d.SubscriptionID)
	}
	return nil
}

func (r *pgDeliveryRepo) GetByID(ctx context.Context, id string) (*domain.Delivery, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	row := r.pool.QueryRow(ctx, selectDelSQL+`WHERE id = $1::uuid`, id)
	d, err := scanDelivery(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errx.New(errx.ErrDeliveryNotFound, "delivery 不存在").WithFields("id", id)
	}
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "notify.repo: get delivery").WithFields("id", id)
	}
	return d, nil
}

func (r *pgDeliveryRepo) List(ctx context.Context, f DeliveryFilter, p Page) ([]*domain.Delivery, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "notify.repo: nil pool")
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
	if strings.TrimSpace(f.SubscriptionID) != "" {
		args = append(args, f.SubscriptionID)
		clauses = append(clauses, "subscription_id = $"+itoa(len(args))+"::uuid")
	}
	if strings.TrimSpace(f.Status) != "" {
		args = append(args, f.Status)
		clauses = append(clauses, "status = $"+itoa(len(args)))
	}
	if strings.TrimSpace(f.EventKind) != "" {
		args = append(args, f.EventKind)
		clauses = append(clauses, "event_kind = $"+itoa(len(args)))
	}
	where := "WHERE " + strings.Join(clauses, " AND ")

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM notification_deliveries `+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list delivery count")
	}

	args = append(args, p.PageSize, (p.Page-1)*p.PageSize)
	q := selectDelSQL + where + ` ORDER BY created_at DESC LIMIT $` + itoa(len(args)-1) + ` OFFSET $` + itoa(len(args))
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list delivery query")
	}
	defer rows.Close()
	out := []*domain.Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "notify.repo: list delivery scan")
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

func (r *pgDeliveryRepo) FetchDue(ctx context.Context, now time.Time, limit int) ([]*domain.Delivery, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, selectDelSQL+`
		WHERE status IN ('pending','failed')
		  AND scheduled_at <= $1
		ORDER BY scheduled_at ASC
		LIMIT $2
	`, now, limit)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "notify.repo: fetch due")
	}
	defer rows.Close()
	out := []*domain.Delivery{}
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "notify.repo: fetch due scan")
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *pgDeliveryRepo) MarkSent(ctx context.Context, id string, sentAt time.Time) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE notification_deliveries
		   SET status = 'sent',
		       sent_at = $2,
		       last_error = NULL,
		       attempts = attempts + 1
		 WHERE id = $1::uuid
	`, id, sentAt)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: mark sent").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrDeliveryNotFound, "delivery 不存在").WithFields("id", id)
	}
	return nil
}

func (r *pgDeliveryRepo) MarkFailed(ctx context.Context, id string, lastErr string, next *time.Time) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "notify.repo: nil pool")
	}
	// next 为 nil → 转 dead；否则 status=failed + scheduled_at=next
	if next == nil {
		tag, err := r.pool.Exec(ctx, `
			UPDATE notification_deliveries
			   SET status = 'dead',
			       last_error = $2,
			       attempts = attempts + 1
			 WHERE id = $1::uuid
		`, id, truncErr(lastErr))
		if err != nil {
			return errx.Wrap(errx.ErrDatabase, err, "notify.repo: mark dead").WithFields("id", id)
		}
		if tag.RowsAffected() == 0 {
			return errx.New(errx.ErrDeliveryNotFound, "delivery 不存在").WithFields("id", id)
		}
		return nil
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE notification_deliveries
		   SET status = 'failed',
		       last_error = $2,
		       attempts = attempts + 1,
		       scheduled_at = $3
		 WHERE id = $1::uuid
	`, id, truncErr(lastErr), *next)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "notify.repo: mark failed").WithFields("id", id)
	}
	if tag.RowsAffected() == 0 {
		return errx.New(errx.ErrDeliveryNotFound, "delivery 不存在").WithFields("id", id)
	}
	return nil
}

func scanDelivery(s interface {
	Scan(dst ...any) error
}) (*domain.Delivery, error) {
	out := &domain.Delivery{}
	var payloadBytes []byte
	var projectID *string
	var eventKind, status string
	if err := s.Scan(
		&out.ID, &out.SubscriptionID, &out.TenantID, &projectID,
		&eventKind, &out.EventTopic, &payloadBytes,
		&status, &out.Attempts, &out.LastError,
		&out.ScheduledAt, &out.CreatedAt, &out.SentAt,
	); err != nil {
		return nil, err
	}
	if projectID != nil && *projectID != "" {
		out.ProjectID = projectID
	}
	out.EventKind = domain.EventKind(eventKind)
	out.Status = domain.DeliveryStatus(status)
	out.Payload = map[string]any{}
	if len(payloadBytes) > 0 {
		_ = json.Unmarshal(payloadBytes, &out.Payload)
	}
	return out, nil
}

// === 辅助 ===

func nullableUUID(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullableUUIDPtr(p *string) any {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return *p
}

func itoa(n int) string { return strconv.Itoa(n) }

const lastErrorMaxLen = 1024

// truncErr 防 last_error 太长把日志炸了。
func truncErr(s string) string {
	if len(s) <= lastErrorMaxLen {
		return s
	}
	return s[:lastErrorMaxLen] + "…(truncated)"
}
