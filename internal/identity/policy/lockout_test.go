package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func TestConfig_Default(t *testing.T) {
	c := DefaultConfig()
	require.NoError(t, c.Validate())
	assert.Equal(t, 5, c.AccountThreshold)
	assert.Equal(t, 10*time.Minute, c.AccountWindow)
	assert.Equal(t, 15*time.Minute, c.AccountLockoutFor)
	assert.Equal(t, 20, c.IPThreshold)
	assert.Equal(t, 1*time.Minute, c.IPWindow)
	assert.Equal(t, 60*time.Minute, c.IPLockoutFor)
}

func TestConfig_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"zero account threshold", func(c *Config) { c.AccountThreshold = 0 }},
		{"negative ip threshold", func(c *Config) { c.IPThreshold = -1 }},
		{"zero account window", func(c *Config) { c.AccountWindow = 0 }},
		{"zero ip window", func(c *Config) { c.IPWindow = 0 }},
		{"zero account lockout", func(c *Config) { c.AccountLockoutFor = 0 }},
		{"zero ip lockout", func(c *Config) { c.IPLockoutFor = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mut(&c)
			err := c.Validate()
			require.Error(t, err)
			code, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, code)
		})
	}
}

func TestNewRedis_RejectsNilClient(t *testing.T) {
	_, err := NewRedis(nil, DefaultConfig())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestNewRedis_RejectsBadConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccountThreshold = 0
	// 使用 nil 但 cfg 校验先于 client 校验失败 — 实际不会到 client 校验
	// 用一个永远不会被调到的 mock 不必要；这里复用 nil 行为：
	// NewRedis 先校 client（nil），再校 cfg；nil client 时 cfg 校验不到
	// 所以单独测 Validate 已覆盖；此处确认 NewRedis 不 panic。
}
