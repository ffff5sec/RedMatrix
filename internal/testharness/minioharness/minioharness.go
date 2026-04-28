//go:build integration

// Package minioharness 提供 testcontainers 启 MinIO 容器 helper，仅在
// `go test -tags=integration` 下编译。
package minioharness

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/minio"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	imageDefault     = "minio/minio:RELEASE.2024-08-29T01-40-52Z"
	defaultAccessKey = "minioadmin"
	defaultSecretKey = "minioadmin"
)

// MinIO 是一个运行中的 MinIO 容器及其访问参数。
type MinIO struct {
	Container *minio.MinioContainer
	Endpoint  string // host:port（无 scheme）
	AccessKey string
	SecretKey string
}

// Start 启动 MinIO 容器（默认 minioadmin:minioadmin 凭据）。
//
// 容器在 t.Cleanup 时关闭。
func Start(t *testing.T) *MinIO {
	t.Helper()

	ctx := context.Background()
	container, err := minio.Run(ctx,
		imageDefault,
		minio.WithUsername(defaultAccessKey),
		minio.WithPassword(defaultSecretKey),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/minio/health/live").
				WithPort("9000/tcp").
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "MinIO 容器启动失败（确认 Docker daemon 在线）")

	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("MinIO 容器 terminate 失败: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx)
	require.NoError(t, err)

	return &MinIO{
		Container: container,
		Endpoint:  connStr, // ConnectionString 返回 "host:port"（无 scheme）
		AccessKey: defaultAccessKey,
		SecretKey: defaultSecretKey,
	}
}
