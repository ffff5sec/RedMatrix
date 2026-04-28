package eventbus

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Record 是 outbox_events 表的一行（仅 Relay 关心的字段）。
type Record struct {
	ID        string
	Topic     string
	Payload   []byte
	Attempts  int
	CreatedAt time.Time
	LastError string
}

// Stats 是 outbox 队列的当前快照（监控指标用）。
type Stats struct {
	Pending         int64
	FailedPermanent int64
}

// Outbox 封装 outbox_events 表的 Relay-side 操作。
// 业务代码通过 PublishTx 顶层函数写入（不需要 Outbox 实例）。
type Outbox struct {
	pool *pgxpool.Pool
}

// NewOutbox 构造 Outbox。pool 应为 redmatrix_maintenance 池（Relay 跨租户扫描）。
func NewOutbox(pool *pgxpool.Pool) *Outbox {
	return &Outbox{pool: pool}
}

// PublishTx 把 ev 写入当前 tx 的 outbox_events。
// 调用方在同一 tx 内还可写自己的业务行（保证原子性）。
// tx commit 之后 Relay 才能扫到该事件并异步分发。
//
// 失败返回 *errx.DomainError（ErrInternal / ErrDatabase）。
func PublishTx[T Event](ctx context.Context, tx pgx.Tx, ev T) error {
	if tx == nil {
		return errx.New(errx.ErrInternal, "eventbus: PublishTx 需要非 nil tx")
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return errx.Wrap(errx.ErrInternal, err, "eventbus: marshal event payload").
			WithFields("topic", ev.Topic())
	}
	traceID := traceIDFromContext(ctx)
	tenantID := tenantIDFromContext(ctx)

	_, err = tx.Exec(ctx, `
		INSERT INTO outbox_events (topic, payload, tenant_id, trace_id)
		VALUES ($1, $2::jsonb, $3, $4)
	`, ev.Topic(), payload, nullableUUID(tenantID), nullableString(traceID))
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "eventbus: insert outbox row").
			WithFields("topic", ev.Topic())
	}
	return nil
}

// Pending 返回最多 limit 条尚未 published 且 next_attempt_at <= now() 的事件，
// 按 created_at 升序（最早事件先处理）。
//
// 注：未用 SELECT FOR UPDATE SKIP LOCKED；Phase 1 假设单 Relay 实例。
// 多实例场景需在 Phase 2 加锁；详见 LLD 20-eventbus-impl §6.4。
func (o *Outbox) Pending(ctx context.Context, limit int) ([]Record, error) {
	if o == nil || o.pool == nil {
		return nil, errx.New(errx.ErrInternal, "eventbus: Outbox 未初始化")
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := o.pool.Query(ctx, `
		SELECT id::text, topic, payload, attempts, created_at, COALESCE(last_error, '')
		  FROM outbox_events
		 WHERE published_at IS NULL
		   AND failed_permanently_at IS NULL
		   AND next_attempt_at <= now()
		 ORDER BY created_at
		 LIMIT $1
	`, limit)
	if err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "eventbus: query pending outbox")
	}
	defer rows.Close()

	out := make([]Record, 0, limit)
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Topic, &r.Payload, &r.Attempts, &r.CreatedAt, &r.LastError); err != nil {
			return nil, errx.Wrap(errx.ErrDatabase, err, "eventbus: scan outbox row")
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, errx.Wrap(errx.ErrDatabase, err, "eventbus: outbox rows iter")
	}
	return out, nil
}

// MarkPublished 标记 id 已成功投递。published_at = now()。
func (o *Outbox) MarkPublished(ctx context.Context, id string) error {
	if o == nil || o.pool == nil {
		return errx.New(errx.ErrInternal, "eventbus: Outbox 未初始化")
	}
	_, err := o.pool.Exec(ctx, `
		UPDATE outbox_events SET published_at = now()
		 WHERE id = $1::uuid AND published_at IS NULL
	`, id)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "eventbus: mark published").WithFields("id", id)
	}
	return nil
}

// MarkFailed 增加 attempts，记 last_error，更新 next_attempt_at。
// permanent=true 时设 failed_permanently_at = now()（停止重试）。
func (o *Outbox) MarkFailed(ctx context.Context, id, lastErr string, nextDelay time.Duration, permanent bool) error {
	if o == nil || o.pool == nil {
		return errx.New(errx.ErrInternal, "eventbus: Outbox 未初始化")
	}
	if permanent {
		_, err := o.pool.Exec(ctx, `
			UPDATE outbox_events
			   SET attempts = attempts + 1,
			       last_error = $2,
			       failed_permanently_at = now()
			 WHERE id = $1::uuid
		`, id, truncateError(lastErr))
		if err != nil {
			return errx.Wrap(errx.ErrDatabase, err, "eventbus: mark failed permanent").WithFields("id", id)
		}
		return nil
	}
	intervalMs := nextDelay.Milliseconds()
	if intervalMs < 0 {
		intervalMs = 0
	}
	_, err := o.pool.Exec(ctx, `
		UPDATE outbox_events
		   SET attempts = attempts + 1,
		       last_error = $2,
		       next_attempt_at = now() + ($3::bigint || ' milliseconds')::interval
		 WHERE id = $1::uuid
	`, id, truncateError(lastErr), intervalMs)
	if err != nil {
		return errx.Wrap(errx.ErrDatabase, err, "eventbus: mark failed transient").WithFields("id", id)
	}
	return nil
}

// Stats 返回 pending / failed_permanent 计数（监控用；不含已 published）。
func (o *Outbox) Stats(ctx context.Context) (Stats, error) {
	if o == nil || o.pool == nil {
		return Stats{}, errx.New(errx.ErrInternal, "eventbus: Outbox 未初始化")
	}
	row := o.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE published_at IS NULL AND failed_permanently_at IS NULL),
		  COUNT(*) FILTER (WHERE failed_permanently_at IS NOT NULL)
		  FROM outbox_events
	`)
	var s Stats
	if err := row.Scan(&s.Pending, &s.FailedPermanent); err != nil {
		return Stats{}, errx.Wrap(errx.ErrDatabase, err, "eventbus: outbox stats")
	}
	return s, nil
}

// === 辅助 ===

// truncateError 把 error 字符串截到 1024 字节（last_error 列防失控膨胀）。
func truncateError(s string) string {
	const maxLen = 1024
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// nullableString 把空串转为 nil（pgx 让 nil 写 NULL）。
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableUUID 把空 UUID 字串转为 nil。pg ::uuid 类型不接受空串。
func nullableUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// === ctx 元数据钩子（与 internal/platform/log.WithRequestID/WithTenantID 兼容）===
//
// 我们不直接 import log 包以免循环：用 context.Value + log 内部 ctxKey 类型相同
// 不可行（unexported）。这里复制 string-key 对照，等 internal/platform/ctxmeta
// 抽出独立包后切换。
//
// 临时方案：只支持调用方手动通过下面 helper 把 traceID/tenantID 设入 ctx；
// log 包的 ctx-aware helper 暂不与 outbox 联动（next PR 的 ctxmeta 包统一）。

type outboxCtxKey int

const (
	ctxKeyTraceID outboxCtxKey = iota
	ctxKeyTenantID
)

// WithTraceID 把 trace ID 注入 ctx，PublishTx 写 outbox.trace_id 时取此值。
// 业务代码可在 RPC 拦截器层完成注入，以便事件全链路追溯。
func WithTraceID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyTraceID, id)
}

// WithTenantID 同上。tenant_id 主要用于审计与按租户维度的指标聚合。
func WithTenantID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyTenantID, id)
}

func traceIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(ctxKeyTraceID).(string)
	return v
}

func tenantIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(ctxKeyTenantID).(string)
	return v
}
