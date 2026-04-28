package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// 不可达 URL：127.0.0.1:1 端口必然 ECONNREFUSED。
const unreachableURL = "redis://:pw@127.0.0.1:1/0"

// fastTestConfig 不主动建 idle 连接，避免不可达测试卡住。
func fastTestConfig() Config {
	return Config{
		URL:          unreachableURL,
		PoolSize:     2,
		MinIdleConns: 0,
	}
}

// === Open ===

func TestOpenLazyDoesNotConnect(t *testing.T) {
	c, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err)
	require.NotNil(t, c)
	defer c.Close()
}

func TestOpenRequiresURL(t *testing.T) {
	_, err := Open(context.Background(), Config{})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "REDIS_URL", de.Fields["var"])
}

func TestOpenInvalidURL(t *testing.T) {
	_, err := Open(context.Background(), Config{URL: "not a redis url"})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

// === Ping ===

func TestPingFailsOnUnreachable(t *testing.T) {
	c, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err = c.Ping(ctx)
	require.Error(t, err)

	code, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, code)
}

func TestPingNilClient(t *testing.T) {
	var c *Client
	err := c.Ping(context.Background())
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, code)
}

func TestPingEmbeddedNil(t *testing.T) {
	c := &Client{} // 内部 *redis.Client 是 nil
	err := c.Ping(context.Background())
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, code)
}

// === Close ===

func TestCloseNilSafe(t *testing.T) {
	var c *Client
	assert.NoError(t, c.Close())
}

func TestCloseEmptyClientSafe(t *testing.T) {
	c := &Client{}
	assert.NoError(t, c.Close())
}

// === Stats ===

func TestStats(t *testing.T) {
	c, err := Open(context.Background(), fastTestConfig())
	require.NoError(t, err)
	defer c.Close()

	s := c.Stats()
	assert.NotNil(t, s)
}

func TestStatsNilClient(t *testing.T) {
	var c *Client
	assert.Nil(t, c.Stats())
}

// === Sanitize ===

func TestSanitizeRedactsPassword(t *testing.T) {
	in := "redis://:supersecret@host:6379/0"
	out := Sanitize(in)
	assert.NotContains(t, out, "supersecret")
	// userinfo 被 url.URL.Redacted 替换为 ":xxxxx" 形式
	assert.Contains(t, out, "host:6379")
}

func TestSanitizeNoUserInfo(t *testing.T) {
	in := "redis://host:6379/0"
	out := Sanitize(in)
	assert.Equal(t, in, out)
}

func TestSanitizeEmpty(t *testing.T) {
	assert.Equal(t, "", Sanitize(""))
}

func TestSanitizeInvalid(t *testing.T) {
	out := Sanitize("redis://%%%@host/0")
	assert.Equal(t, "<invalid redis url>", out)
}

// === withDefaults ===

func TestWithDefaultsZeroFillsAll(t *testing.T) {
	cfg := withDefaults(Config{})
	assert.Equal(t, defaultMinIdleConns, cfg.MinIdleConns)
	assert.Equal(t, defaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, defaultDialTimeout, cfg.DialTimeout)
	assert.Equal(t, defaultReadTimeout, cfg.ReadTimeout)
	assert.Equal(t, defaultWriteTimeout, cfg.WriteTimeout)
}

func TestWithDefaultsExplicitPoolSizeKeepsMinIdleZero(t *testing.T) {
	// 关键不变量：PoolSize 显式 > 0 时不再回填 MinIdleConns。
	// 否则不可达 URL 测试场景会被默认 idle 触发后台重连拖死。
	cfg := withDefaults(Config{PoolSize: 2, MinIdleConns: 0})
	assert.Equal(t, 0, cfg.MinIdleConns)
}

func TestWithDefaultsRetryRespected(t *testing.T) {
	cfg := withDefaults(Config{MaxRetries: 1})
	assert.Equal(t, 1, cfg.MaxRetries)
}

// === errors.As 行为 ===

func TestPingErrorIsDomainError(t *testing.T) {
	c, err := Open(context.Background(), fastTestConfig())
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
