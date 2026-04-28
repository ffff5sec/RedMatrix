//go:build integration

package eventbus

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
)

// applyMigrations 跑 goose Up 把 outbox_events 表落库（迁移 0003）。
// 然后返回连接 pool（用 admin role —— maintenance role 也能用，但 admin 更省事）。
func setupOutboxDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	h := pgharness.Start(t)

	db, err := sql.Open("pgx", h.AdminDSN)
	require.NoError(t, err)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	require.NoError(t, migrate.Up(ctx, db))

	pool, err := pgxpool.New(ctx, h.AdminDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestPublishTx_RoundTrip(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)

	ev := AssetCreated{AssetID: "ast_1", TenantID: "t_1"}
	require.NoError(t, PublishTx(ctx, tx, ev))
	require.NoError(t, tx.Commit(ctx))

	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	assert.Equal(t, ev.Topic(), pending[0].Topic)
	assert.JSONEq(t, `{"AssetID":"ast_1","TenantID":"t_1"}`, string(pending[0].Payload))
	assert.Equal(t, 0, pending[0].Attempts)
}

func TestPublishTx_TraceAndTenantInjected(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)

	ctx := ctxmeta.WithRequestID(context.Background(), "req_abc")
	ctx = ctxmeta.WithTenantID(ctx, "11111111-1111-1111-1111-111111111111")

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "x"}))
	require.NoError(t, tx.Commit(ctx))

	// 直接读底层表验证 trace_id / tenant_id 已写入
	var traceID, tenantID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(trace_id, ''), COALESCE(tenant_id::text, '')
		  FROM outbox_events LIMIT 1
	`).Scan(&traceID, &tenantID))
	assert.Equal(t, "req_abc", traceID)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", tenantID)

	// pending 数据中也有该条
	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, pending, 1)
}

func TestPublishTx_RollbackDropsRow(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "rolled-back"}))
	require.NoError(t, tx.Rollback(ctx))

	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pending, "rollback 必须丢弃 outbox 行（原子性）")
}

func TestMarkPublished_AndPendingFiltering(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)
	ctx := context.Background()

	// Insert two events
	for i := 0; i < 2; i++ {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "x"}))
		require.NoError(t, tx.Commit(ctx))
	}

	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)

	// Mark one published
	require.NoError(t, outbox.MarkPublished(ctx, pending[0].ID))

	pending2, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, pending2, 1, "已 published 的不应再返回")
	assert.Equal(t, pending[1].ID, pending2[0].ID)
}

func TestMarkFailed_BumpsAttemptsAndDelay(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "x"}))
	require.NoError(t, tx.Commit(ctx))

	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	rec := pending[0]

	require.NoError(t, outbox.MarkFailed(ctx, rec.ID, "boom", 200*time.Millisecond, false))

	// 立即查 → next_attempt_at 在未来 → 不应在 pending 中
	pending2, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pending2, "next_attempt_at 未到，应被过滤")

	// 等到延迟过去后再查
	time.Sleep(300 * time.Millisecond)
	pending3, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending3, 1)
	assert.Equal(t, 1, pending3[0].Attempts)
	assert.Equal(t, "boom", pending3[0].LastError)
}

func TestMarkFailed_PermanentNeverRetried(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "x"}))
	require.NoError(t, tx.Commit(ctx))

	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)

	require.NoError(t, outbox.MarkFailed(ctx, pending[0].ID, "permanent boom", 0, true))

	pending2, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	assert.Empty(t, pending2, "failed_permanently 行不再重试")

	// stats 应反映失败计数
	stats, err := outbox.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.Pending)
	assert.Equal(t, int64(1), stats.FailedPermanent)
}

func TestStats_PendingAndFailed(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)
	ctx := context.Background()

	// 3 事件：1 成功 / 1 失败 perma / 1 pending
	for i := 0; i < 3; i++ {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "x"}))
		require.NoError(t, tx.Commit(ctx))
	}
	pending, err := outbox.Pending(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 3)

	require.NoError(t, outbox.MarkPublished(ctx, pending[0].ID))
	require.NoError(t, outbox.MarkFailed(ctx, pending[1].ID, "x", 0, true))

	stats, err := outbox.Stats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.Pending)
	assert.Equal(t, int64(1), stats.FailedPermanent)
}

func TestRelay_DispatchesAndMarksPublished(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)

	bus := New(nil)
	registry := NewRegistry()
	RegisterType[AssetCreated](registry)

	got := make(chan AssetCreated, 4)
	Subscribe[AssetCreated](bus, func(_ context.Context, ev AssetCreated) error {
		got <- ev
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Publish 3 events
	for i := 0; i < 3; i++ {
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "ast_" + string(rune('a'+i))}))
		require.NoError(t, tx.Commit(ctx))
	}

	relay := NewRelay(outbox, bus, registry, RelayConfig{
		PollInterval: 100 * time.Millisecond,
		BatchSize:    10,
		MaxAttempts:  3,
		JitterRatio:  0.01, // 让退避近乎确定
	}, nil)

	go func() {
		_ = relay.Run(ctx)
	}()

	// 等所有 3 事件被 handler 收到
	timeout := time.After(5 * time.Second)
	received := 0
	for received < 3 {
		select {
		case <-got:
			received++
		case <-timeout:
			t.Fatalf("Relay 未在 5 秒内派发全部 3 事件（已收 %d）", received)
		}
	}

	cancel()

	// 全部应已 published（pending=0）
	stats, err := outbox.Stats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(0), stats.Pending)
}

func TestRelay_HandlerErrorRetriedThenPermanent(t *testing.T) {
	pool := setupOutboxDB(t)
	outbox := NewOutbox(pool)

	bus := New(nil)
	registry := NewRegistry()
	RegisterType[AssetCreated](registry)

	calls := make(chan struct{}, 10)
	Subscribe[AssetCreated](bus, func(_ context.Context, _ AssetCreated) error {
		calls <- struct{}{}
		return assert.AnError // 永远失败
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, PublishTx(ctx, tx, AssetCreated{AssetID: "always-fails"}))
	require.NoError(t, tx.Commit(ctx))

	relay := NewRelay(outbox, bus, registry, RelayConfig{
		PollInterval:   50 * time.Millisecond,
		BatchSize:      10,
		MaxAttempts:    3, // attempts: 1, 2, 3 → permanent
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
		JitterRatio:    0.01,
	}, nil)
	go func() { _ = relay.Run(ctx) }()

	// 收到 3 次调用就应该 permanent
	timeout := time.After(5 * time.Second)
	received := 0
	for received < 3 {
		select {
		case <-calls:
			received++
		case <-timeout:
			t.Fatalf("handler 未被调 3 次（实际 %d）", received)
		}
	}

	// 给 Relay 足够时间标记 permanent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := outbox.Stats(context.Background())
		require.NoError(t, err)
		if stats.FailedPermanent == 1 {
			cancel()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	stats, _ := outbox.Stats(context.Background())
	t.Fatalf("3 次失败后应 failed_permanently；实际 stats=%+v", stats)
}
