package policy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func TestCaptchaConfig_Default(t *testing.T) {
	c := DefaultCaptchaConfig()
	require.NoError(t, c.Validate())
	assert.True(t, c.Enabled)
	assert.True(t, c.AlwaysShow)
	assert.Equal(t, 6, c.Length)
	assert.Equal(t, 5*time.Minute, c.TTL)
}

func TestCaptchaConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*CaptchaConfig)
		wantOK  bool
		wantErr errx.Code
	}{
		{"default", func(c *CaptchaConfig) {}, true, ""},
		{"disabled skips other checks", func(c *CaptchaConfig) {
			c.Enabled = false
			c.Length = 0
		}, true, ""},
		{"length too short", func(c *CaptchaConfig) { c.Length = 3 }, false, errx.ErrInvalidInput},
		{"length too long", func(c *CaptchaConfig) { c.Length = 7 }, false, errx.ErrInvalidInput},
		{"zero width", func(c *CaptchaConfig) { c.Width = 0 }, false, errx.ErrInvalidInput},
		{"zero height", func(c *CaptchaConfig) { c.Height = 0 }, false, errx.ErrInvalidInput},
		{"zero TTL", func(c *CaptchaConfig) { c.TTL = 0 }, false, errx.ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultCaptchaConfig()
			tc.mut(&c)
			err := c.Validate()
			if tc.wantOK {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			code, _ := errx.GetCode(err)
			assert.Equal(t, tc.wantErr, code)
		})
	}
}

func TestNewRedisCaptcha_NilClient(t *testing.T) {
	_, err := NewRedisCaptcha(nil, DefaultCaptchaConfig())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestDigitsToString(t *testing.T) {
	got := digitsToString([]byte{1, 2, 3, 4, 5, 6})
	assert.Equal(t, "123456", got)
}

// IsRequired 不依赖 Redis 也能测（直接构造 redisCaptcha，client 字段不会被读到）。
func TestIsRequired_DependsOnConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CaptchaConfig)
		want   bool
	}{
		{"enabled+always_show → true", func(c *CaptchaConfig) {}, true},
		{"disabled → false", func(c *CaptchaConfig) { c.Enabled = false }, false},
		{"enabled+!always_show → false (selective TODO)", func(c *CaptchaConfig) { c.AlwaysShow = false }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultCaptchaConfig()
			tc.mutate(&cfg)
			rc := &redisCaptcha{cfg: cfg}
			got := rc.IsRequired(t.Context(),
				netip.MustParseAddr("203.0.113.1"), "user-1")
			assert.Equal(t, tc.want, got)
		})
	}
}
