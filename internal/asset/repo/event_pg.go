// event_pg.go PR-S57 —— asset_events PG 实现。
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

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

// strconvI 局部 helper：int → "1" / "2" / ... (避免大量 strconv.Itoa 噪音)。
// 引用其它文件已有的 itoa 时改名为 strconvI 防冲突。
func strconvI(i int) string {
	// 取自 internal pgx 风格；与 pg.go 的 itoa 等价。
	return itoa(i)
}
