package minio

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

const (
	unreachableEndpoint = "127.0.0.1:1"
	testAccessKey       = "AKIATESTKEY1234"
	testSecretKey       = "SECRET-test-1234567890"
)

// === Open ===

func TestOpenSuccess(t *testing.T) {
	c, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	defer c.Close()
}

func TestOpenRequiresEndpoint(t *testing.T) {
	_, err := Open(context.Background(), Config{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "MINIO_ENDPOINT", de.Fields["var"])
}

func TestOpenRequiresAccessKey(t *testing.T) {
	_, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		SecretKey: testSecretKey,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

func TestOpenRequiresSecretKey(t *testing.T) {
	_, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		AccessKey: testAccessKey,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

func TestOpenRejectsSchemeInEndpoint(t *testing.T) {
	_, err := Open(context.Background(), Config{
		Endpoint:  "http://" + unreachableEndpoint,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

// === Ping ===

func TestPingFailsOnUnreachable(t *testing.T) {
	c, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = c.Ping(ctx)
	require.Error(t, err)
	c2, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c2)
}

func TestPingNilClient(t *testing.T) {
	var c *Client
	err := c.Ping(context.Background())
	require.Error(t, err)
	c2, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c2)
}

func TestPingEmbeddedNil(t *testing.T) {
	c := &Client{}
	err := c.Ping(context.Background())
	require.Error(t, err)
	c2, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c2)
}

// === VerifyBuckets / EnsureBuckets nil safety ===

func TestVerifyBucketsNilClient(t *testing.T) {
	var c *Client
	err := c.VerifyBuckets(context.Background(), RequiredBuckets)
	require.Error(t, err)
	c2, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c2)
}

func TestEnsureBucketsNilClient(t *testing.T) {
	var c *Client
	err := c.EnsureBuckets(context.Background(), RequiredBuckets, "")
	require.Error(t, err)
	c2, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, c2)
}

// === Close 安全性 ===

func TestCloseNilSafe(t *testing.T) {
	var c *Client
	assert.NoError(t, c.Close())
}

func TestCloseAlwaysOK(t *testing.T) {
	c, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.NoError(t, err)
	assert.NoError(t, c.Close())
	assert.NoError(t, c.Close()) // 二次 Close 也不报错
}

// === Sanitize ===

func TestSanitizeMaskedAccessKey(t *testing.T) {
	out := Sanitize("minio:9000", "AKIATESTKEY1234")
	assert.Contains(t, out, "minio:9000")
	assert.NotContains(t, out, "AKIATESTKEY1234")
	assert.Contains(t, out, "AKIA***1234")
}

func TestSanitizeShortAccessKeyAllMasked(t *testing.T) {
	out := Sanitize("minio:9000", "abc")
	assert.Equal(t, "minio:9000 (key=***)", out)
}

func TestSanitizeNoEndpoint(t *testing.T) {
	out := Sanitize("", "AKIATEST1234567")
	assert.NotContains(t, out, "AKIATEST1234567")
}

func TestSanitizeAllEmpty(t *testing.T) {
	assert.Equal(t, "", Sanitize("", ""))
}

// === EndpointHTTPURL ===

func TestEndpointHTTPURL(t *testing.T) {
	tests := []struct {
		ep   string
		ssl  bool
		want string
	}{
		{"minio:9000", false, "http://minio:9000"},
		{"minio.example.com:9000", true, "https://minio.example.com:9000"},
		{"", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.ep, func(t *testing.T) {
			assert.Equal(t, tt.want, EndpointHTTPURL(tt.ep, tt.ssl))
		})
	}
}

// === RequiredBuckets 不变量 ===

func TestRequiredBucketsListIsSane(t *testing.T) {
	assert.Len(t, RequiredBuckets, 9, "01 §3.4 / 40 §4.4 列出 9 个 bucket")

	// 全部以 redmatrix- 开头，全小写
	seen := map[string]bool{}
	for _, b := range RequiredBuckets {
		assert.True(t, strings.HasPrefix(b, "redmatrix-"),
			"bucket %s 应以 redmatrix- 开头", b)
		assert.Equal(t, strings.ToLower(b), b, "bucket %s 应全小写（S3 限制）", b)
		assert.False(t, seen[b], "bucket %s 重复", b)
		seen[b] = true
	}

	// 关键 bucket 必须在列表里
	for _, must := range []string{
		"redmatrix-plugins",
		"redmatrix-audit-archive",
		"redmatrix-backups",
		"redmatrix-reports",
	} {
		assert.True(t, seen[must], "缺关键 bucket %s", must)
	}
}

// === errors.As 行为 ===

func TestPingErrorIsDomainError(t *testing.T) {
	c, err := Open(context.Background(), Config{
		Endpoint:  unreachableEndpoint,
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
	})
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = c.Ping(ctx)
	require.Error(t, err)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, de.Code)
}
