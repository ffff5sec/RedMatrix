// event_pg.go PR-S57 —— asset_events PG 实现。
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

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

type pgEventRepo struct {
	pool *pgxpool.Pool
}

// NewEventPG 构造 PG 实现。
func NewEventPG(pool *pgxpool.Pool) EventRepository {
	return &pgEventRepo{pool: pool}
}

const eventSelectSQL = `
SELECT id::text,
       tenant_id::text,
       project_id::text,
       asset_id::text,
       event_kind,
       payload,
       created_at
FROM asset_events
`

func (r *pgEventRepo) Insert(ctx context.Context, e *domain.Event) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "asset.event_repo: nil pool")
	}
	if err := e.ValidateForCreate(); err != nil {
		return err
	}
	payloadJSON, err := json.Marshal(e.Payload)
	if err != nil {
		return errx.Wrap(errx.ErrInvalidInput, err, "event.payload not marshalable")
	}
	q := `INSERT INTO asset_events (tenant_id, project_id, asset_id, event_kind, payload)
	      VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb)
	      RETURNING id::text, created_at`
	var assetIDArg any
	if e.AssetID != nil {
		assetIDArg = *e.AssetID
	}
	if err := r.pool.QueryRow(ctx, q, e.TenantID, e.ProjectID, assetIDArg, string(e.Kind), string(payloadJSON)).
		Scan(&e.ID, &e.CreatedAt); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: insert")
	}
	return nil
}

func (r *pgEventRepo) InsertBulk(ctx context.Context, events []*domain.Event) error {
	if r == nil || r.pool == nil {
		return errx.New(errx.ErrInternal, "asset.event_repo: nil pool")
	}
	if len(events) == 0 {
		return nil
	}
	// 用单个 INSERT VALUES (...), (...), (...) 一次写多行
	values := ""
	args := []any{}
	for i, e := range events {
		if err := e.ValidateForCreate(); err != nil {
			return err
		}
		payloadJSON, err := json.Marshal(e.Payload)
		if err != nil {
			return errx.Wrap(errx.ErrInvalidInput, err, "event.payload not marshalable")
		}
		if i > 0 {
			values += ", "
		}
		base := i*5 + 1
		values += "($" + strconvI(base) + "::uuid, $" + strconvI(base+1) + "::uuid, $" +
			strconvI(base+2) + ", $" + strconvI(base+3) + ", $" + strconvI(base+4) + "::jsonb)"
		var assetIDArg any
		if e.AssetID != nil {
			assetIDArg = *e.AssetID
		}
		args = append(args, e.TenantID, e.ProjectID, assetIDArg, string(e.Kind), string(payloadJSON))
	}
	q := `INSERT INTO asset_events (tenant_id, project_id, asset_id, event_kind, payload) VALUES ` + values
	if _, err := r.pool.Exec(ctx, q, args...); err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: insert bulk")
	}
	return nil
}

func (r *pgEventRepo) List(ctx context.Context, f EventFilter, p Page) ([]*domain.Event, int, error) {
	if r == nil || r.pool == nil {
		return nil, 0, errx.New(errx.ErrInternal, "asset.event_repo: nil pool")
	}
	clauses := []string{}
	args := []any{}
	if v := strings.TrimSpace(f.TenantID); v != "" {
		args = append(args, v)
		clauses = append(clauses, "tenant_id = $"+strconvI(len(args))+"::uuid")
	}
	if v := strings.TrimSpace(f.ProjectID); v != "" {
		args = append(args, v)
		clauses = append(clauses, "project_id = $"+strconvI(len(args))+"::uuid")
	} else if f.ProjectIDs != nil {
		if len(f.ProjectIDs) == 0 {
			return []*domain.Event{}, 0, nil
		}
		args = append(args, f.ProjectIDs)
		clauses = append(clauses, "project_id = ANY($"+strconvI(len(args))+"::uuid[])")
	}
	if f.Kind != "" {
		args = append(args, string(f.Kind))
		clauses = append(clauses, "event_kind = $"+strconvI(len(args)))
	}
	if v := strings.TrimSpace(f.AssetID); v != "" {
		args = append(args, v)
		clauses = append(clauses, "asset_id = $"+strconvI(len(args))+"::uuid")
	}
	if f.TimeFrom != nil {
		args = append(args, *f.TimeFrom)
		clauses = append(clauses, "created_at >= $"+strconvI(len(args)))
	}
	if f.TimeTo != nil {
		args = append(args, *f.TimeTo)
		clauses = append(clauses, "created_at <= $"+strconvI(len(args)))
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	// total
	var total int
	if err := r.pool.QueryRow(ctx, "SELECT count(*) FROM asset_events"+where, args...).Scan(&total); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: count")
	}

	page := p.Page
	if page <= 0 {
		page = 1
	}
	size := p.PageSize
	if size <= 0 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	args = append(args, size, (page-1)*size)
	q := eventSelectSQL + where + " ORDER BY created_at DESC LIMIT $" + strconvI(len(args)-1) + " OFFSET $" + strconvI(len(args))

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: list")
	}
	defer rows.Close()
	out := []*domain.Event{}
	for rows.Next() {
		e := &domain.Event{}
		var assetID *string
		var payloadJSON []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ProjectID, &assetID, &e.Kind, &payloadJSON, &e.CreatedAt); err != nil {
			return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: scan")
		}
		e.AssetID = assetID
		if len(payloadJSON) > 0 {
			_ = json.Unmarshal(payloadJSON, &e.Payload)
		}
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: rows iter")
	}
	return out, total, nil
}

func (r *pgEventRepo) GetByID(ctx context.Context, id string) (*domain.Event, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "asset.event_repo: nil pool")
	}
	q := eventSelectSQL + ` WHERE id = $1::uuid`
	e := &domain.Event{}
	var assetID *string
	var payloadJSON []byte
	err := r.pool.QueryRow(ctx, q, id).
		Scan(&e.ID, &e.TenantID, &e.ProjectID, &assetID, &e.Kind, &payloadJSON, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errx.New(errx.ErrAssetNotFound, "asset_event 不存在").WithFields("id", id)
		}
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: get")
	}
	e.AssetID = assetID
	if len(payloadJSON) > 0 {
		_ = json.Unmarshal(payloadJSON, &e.Payload)
	}
	if e.Payload == nil {
		e.Payload = map[string]any{}
	}
	return e, nil
}

// SweepCertsExpiring PR-S59：见 EventRepository.SweepCertsExpiring 注释。
//
// 单条 SQL INSERT ... SELECT + NOT EXISTS 子查询：
//  1. 选 scan_results 里 kind='tls_scan' 且 not_after 落在 (now, now+window] 的行
//  2. 按 (tenant, project, sha256_fingerprint) 去重（DISTINCT ON 取最近一条）
//  3. NOT EXISTS 排除 dedupeWindow 内已有 cert_expiring_soon 事件命中同 fingerprint
//  4. payload 取 host / port / subject_cn / issuer_cn / not_after / fingerprint
//
// 写入失败任一行整体 rollback；返新插入的 *Event 列表（PR-S61 供 notify driver）。
func (r *pgEventRepo) SweepCertsExpiring(ctx context.Context, window, dedupeWindow time.Duration) ([]*domain.Event, error) {
	if r == nil || r.pool == nil {
		return nil, errx.New(errx.ErrInternal, "asset.event_repo: nil pool")
	}
	if window <= 0 || dedupeWindow <= 0 {
		return nil, nil
	}
	q := `
INSERT INTO asset_events (tenant_id, project_id, asset_id, event_kind, payload)
SELECT DISTINCT ON (r.tenant_id, r.project_id, r.data->>'sha256_fingerprint')
       r.tenant_id, r.project_id, NULL, 'cert_expiring_soon',
       jsonb_build_object(
         'host',        r.data->>'host',
         'port',        r.data->>'port',
         'subject_cn',  r.data->>'subject_cn',
         'issuer_cn',   r.data->>'issuer_cn',
         'not_after',   r.data->>'not_after',
         'fingerprint', r.data->>'sha256_fingerprint'
       )
FROM scan_results r
WHERE r.kind = 'tls_scan'
  AND r.data ? 'not_after'
  AND r.data ? 'sha256_fingerprint'
  AND (r.data->>'not_after')::timestamptz > now()
  AND (r.data->>'not_after')::timestamptz <= now() + $1::interval
  AND NOT EXISTS (
    SELECT 1 FROM asset_events e
    WHERE e.event_kind = 'cert_expiring_soon'
      AND e.payload->>'fingerprint' = r.data->>'sha256_fingerprint'
      AND e.created_at > now() - $2::interval
  )
ORDER BY r.tenant_id, r.project_id, r.data->>'sha256_fingerprint', r.created_at DESC
RETURNING id::text, tenant_id::text, project_id::text, event_kind, payload, created_at`
	rows, err := r.pool.Query(ctx, q, intervalArg(window), intervalArg(dedupeWindow))
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: sweep certs expiring")
	}
	defer rows.Close()
	out := []*domain.Event{}
	for rows.Next() {
		e := &domain.Event{}
		var payloadJSON []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.ProjectID, &e.Kind, &payloadJSON, &e.CreatedAt); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: scan sweep certs")
		}
		if len(payloadJSON) > 0 {
			_ = json.Unmarshal(payloadJSON, &e.Payload)
		}
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "asset.event_repo: sweep certs iter")
	}
	return out, nil
}

// intervalArg 把 Go Duration 转成 PG INTERVAL 可接受的字符串（秒数）。
// 用 'N seconds' 字面量，PG 自动转 INTERVAL；规避 driver 的 Duration 编码歧义。
func intervalArg(d time.Duration) string {
	secs := int64(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return strconv.FormatInt(secs, 10) + " seconds"
}

// strconvI 局部 helper：int → "1" / "2" / ... (避免大量 strconv.Itoa 噪音)。
// 引用其它文件已有的 itoa 时改名为 strconvI 防冲突。
func strconvI(i int) string {
	// 取自 internal pgx 风格；与 pg.go 的 itoa 等价。
	return itoa(i)
}
