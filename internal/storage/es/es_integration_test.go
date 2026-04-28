//go:build integration

package es

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/testharness/esharness"
)

// TestOpenAndPing_RealES 验证 Open + Ping 在真实 ES 上工作。
// 单节点档默认 yellow（无副本可分配），Ping 应通过。
func TestOpenAndPing_RealES(t *testing.T) {
	h := esharness.Start(t)

	c, err := Open(context.Background(), Config{URL: h.URL})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, c.Ping(ctx), "ES yellow / green 应通过 Ping")
}

// TestHealth_ReturnsClusterStatus 真实 ES 上获取 cluster status。
func TestHealth_ReturnsClusterStatus(t *testing.T) {
	h := esharness.Start(t)

	c, err := Open(context.Background(), Config{URL: h.URL})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, name, err := c.Health(ctx)
	require.NoError(t, err)
	assert.Contains(t, []string{"yellow", "green"}, status, "单节点档应是 yellow / green")
	assert.NotEmpty(t, name)
}

// TestPing_HTTPNot200 用一个非 ES 的 HTTP 端点测试 IsError 分支
// （此处用 Redis 容器没有 _cluster/health 路径，会返回 404 / connection close。
// 不再起独立容器；用 unreachable URL 已覆盖网络错误分支）。
//
// 完整 4xx/5xx 分支的覆盖留给 httptest 单测（待补；当前 unreachable 已断言
// BOOTSTRAP_DB_UNREACHABLE 路径走通）。

// TestSanitize_RealURL 真实 URL 走 Sanitize 不出错。
func TestSanitize_RealURL(t *testing.T) {
	h := esharness.Start(t)
	out := Sanitize(h.URL)
	assert.Equal(t, h.URL, out, "无 userinfo 的 URL 应原样返回")
	assert.NotContains(t, out, "<invalid")
}
