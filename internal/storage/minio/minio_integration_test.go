//go:build integration

package minio

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/testharness/minioharness"
)

func openReal(t *testing.T) *Client {
	t.Helper()
	h := minioharness.Start(t)
	c, err := Open(context.Background(), Config{
		Endpoint:  h.Endpoint,
		AccessKey: h.AccessKey,
		SecretKey: h.SecretKey,
		UseSSL:    false,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestPing_RealMinIO 真实容器上 Ping 通过。
func TestPing_RealMinIO(t *testing.T) {
	c := openReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, c.Ping(ctx))
}

// TestVerifyBuckets_FailsBeforeBootstrap 全空容器调 VerifyBuckets 应失败 + 含 bucket 字段。
func TestVerifyBuckets_FailsBeforeBootstrap(t *testing.T) {
	c := openReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.VerifyBuckets(ctx, RequiredBuckets)
	require.Error(t, err)

	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapStorageMissing, code)

	var de *errx.DomainError
	require.ErrorAs(t, err, &de)
	// 第一个缺失的 bucket 应被报告
	assert.NotEmpty(t, de.Fields["bucket"])
}

// TestEnsureBuckets_CreatesAll9 EnsureBuckets 创建所有 9 个 bucket，再次 Verify 通过。
func TestEnsureBuckets_CreatesAll9(t *testing.T) {
	c := openReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, c.EnsureBuckets(ctx, RequiredBuckets, ""))
	require.NoError(t, c.VerifyBuckets(ctx, RequiredBuckets), "EnsureBuckets 后 Verify 应通过")

	// 二次 EnsureBuckets 幂等（BucketAlreadyOwnedByYou 容错）
	require.NoError(t, c.EnsureBuckets(ctx, RequiredBuckets, ""))
}

// TestEnsureBuckets_PartialPreExisting 部分 bucket 已存在时仍能补齐其他。
func TestEnsureBuckets_PartialPreExisting(t *testing.T) {
	c := openReal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 先建头两个
	require.NoError(t, c.EnsureBuckets(ctx, RequiredBuckets[:2], ""))
	require.NoError(t, c.VerifyBuckets(ctx, RequiredBuckets[:2]))

	// 再用全列表补齐
	require.NoError(t, c.EnsureBuckets(ctx, RequiredBuckets, ""))
	require.NoError(t, c.VerifyBuckets(ctx, RequiredBuckets))
}
