//go:build integration

// Package redisharness 提供 testcontainers 启 Redis 容器的 helper，仅在
// `go test -tags=integration` 下编译。
package redisharness

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

const imageDefault = "redis:7-alpine"

// Redis 是一个运行中的 Redis 容器及其 URL。
type Redis struct {
	Container *redis.RedisContainer
	URL       string // redis://host:port/0
}

// Start 启动 Redis 容器（无密码，DB 0 默认）。
//
// 容器在 t.Cleanup 时关闭。
func Start(t *testing.T) *Redis {
	t.Helper()

	ctx := context.Background()
	container, err := redis.Run(ctx,
		imageDefault,
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "Redis 容器启动失败（确认 Docker daemon 已运行）")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("Redis 容器 terminate 失败: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	return &Redis{
		Container: container,
		URL:       connStr,
	}
}
