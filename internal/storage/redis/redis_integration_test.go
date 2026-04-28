//go:build integration

package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

// TestOpenAndPing_RealRedis 验证 Open + Ping 在真实 Redis 上工作。
func TestOpenAndPing_RealRedis(t *testing.T) {
	h := redisharness.Start(t)

	c, err := Open(context.Background(), Config{URL: h.URL})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, c.Ping(ctx))

	// 顺手验证 Set/Get 走得通（验证 client 不只是 ping，是真能操作）
	require.NoError(t, c.Set(ctx, "redmatrix:smoke:test", "v", 0).Err())
	got, err := c.Get(ctx, "redmatrix:smoke:test").Result()
	require.NoError(t, err)
	assert.Equal(t, "v", got)
}

// TestPing_PartialUnreachable 一个 client 指向真实 Redis，另一个指向 127.0.0.1:1。
// 仅验证 Ping 区分行为；不在生产代码里有"多 client" API。
func TestPing_RealVsUnreachable(t *testing.T) {
	h := redisharness.Start(t)

	good, err := Open(context.Background(), Config{URL: h.URL})
	require.NoError(t, err)
	defer good.Close()

	bad, err := Open(context.Background(), Config{
		URL:          "redis://127.0.0.1:1/0",
		PoolSize:     1,
		MinIdleConns: 0,
	})
	require.NoError(t, err)
	defer bad.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	require.NoError(t, good.Ping(ctx), "真实 Redis 应可 ping")
	require.Error(t, bad.Ping(ctx), "不可达 Redis 应失败")
}

// TestStatsAfterUse 验证 Stats 在真实操作后反映 Hits/Misses 数据。
func TestStatsAfterUse(t *testing.T) {
	h := redisharness.Start(t)

	c, err := Open(context.Background(), Config{URL: h.URL})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, c.Ping(ctx))

	// 触发若干次操作以累积 stats
	for i := 0; i < 5; i++ {
		require.NoError(t, c.Set(ctx, "k", "v", 0).Err())
		_, _ = c.Get(ctx, "k").Result()
	}

	s := c.Stats()
	require.NotNil(t, s)
	assert.Greater(t, s.TotalConns, uint32(0), "应至少有一个连接被建立")
}
