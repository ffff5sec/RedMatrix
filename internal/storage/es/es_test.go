package es

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

const unreachableURL = "http://127.0.0.1:1"

// === Open ===

func TestOpenLazyDoesNotConnect(t *testing.T) {
	c, err := Open(context.Background(), Config{URL: unreachableURL})
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
	assert.Equal(t, "ES_URL", de.Fields["var"])
}

func TestOpenInvalidScheme(t *testing.T) {
	_, err := Open(context.Background(), Config{URL: "redis://es:9200"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)

	var de *errx.DomainError
	require.ErrorAs(t, err, &de)
	assert.Equal(t, "redis", de.Fields["got_scheme"])
}

func TestOpenMissingHost(t *testing.T) {
	_, err := Open(context.Background(), Config{URL: "http://"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

func TestOpenMultipleAddresses(t *testing.T) {
	c, err := Open(context.Background(), Config{
		URL: "http://es1:9200,http://es2:9200",
	})
	require.NoError(t, err)
	defer c.Close()
}

func TestOpenAllEmptyAddresses(t *testing.T) {
	_, err := Open(context.Background(), Config{URL: ", , ,"})
	require.Error(t, err)
}

func TestOpenWithCredentials(t *testing.T) {
	c, err := Open(context.Background(), Config{
		URL:      unreachableURL,
		Username: "elastic",
		Password: "secret",
	})
	require.NoError(t, err)
	defer c.Close()
}

// === Ping ===

func TestPingFailsOnUnreachable(t *testing.T) {
	c, err := Open(context.Background(), Config{URL: unreachableURL})
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
	c := &Client{}
	err := c.Ping(context.Background())
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapDBUnreachable, code)
}

// === Health ===

func TestHealthNilClient(t *testing.T) {
	var c *Client
	_, _, err := c.Health(context.Background())
	require.Error(t, err)
}

// === Close (no-op for v8) ===

func TestCloseNilSafe(t *testing.T) {
	var c *Client
	assert.NoError(t, c.Close())
}

func TestCloseAlwaysOK(t *testing.T) {
	c, err := Open(context.Background(), Config{URL: unreachableURL})
	require.NoError(t, err)
	assert.NoError(t, c.Close())
	// 二次 Close 也不报错
	assert.NoError(t, c.Close())
}

// === Sanitize ===

func TestSanitizeRedactsPassword(t *testing.T) {
	in := "https://elastic:supersecret@es:9200"
	out := Sanitize(in)
	assert.NotContains(t, out, "supersecret")
	assert.Contains(t, out, "elastic")
	assert.Contains(t, out, "es:9200")
}

func TestSanitizeMultiURL(t *testing.T) {
	in := "http://es1:9200,https://elastic:pw@es2:9200"
	out := Sanitize(in)
	assert.Contains(t, out, "es1:9200")
	assert.Contains(t, out, "es2:9200")
	assert.NotContains(t, out, "pw")
}

func TestSanitizeNoUserInfo(t *testing.T) {
	in := "http://es:9200"
	assert.Equal(t, in, Sanitize(in))
}

func TestSanitizeEmpty(t *testing.T) {
	assert.Equal(t, "", Sanitize(""))
}

func TestSanitizeAllInvalid(t *testing.T) {
	out := Sanitize(",,,")
	assert.Equal(t, "<invalid es url>", out)
}

// === splitAddresses helper ===

func TestSplitAddresses(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"http://es:9200", []string{"http://es:9200"}},
		{"http://es1:9200,http://es2:9200", []string{"http://es1:9200", "http://es2:9200"}},
		{" http://es:9200 ", []string{"http://es:9200"}},
		{",,", nil},
		{"", nil},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := splitAddresses(tt.in)
			if tt.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// === withDefaults ===

func TestWithDefaultsZero(t *testing.T) {
	cfg := withDefaults(Config{})
	assert.Equal(t, defaultMaxRetries, cfg.MaxRetries)
	assert.Equal(t, defaultDialTimeout, cfg.DialTimeout)
}

func TestWithDefaultsExplicit(t *testing.T) {
	cfg := withDefaults(Config{MaxRetries: 5, DialTimeout: 100 * time.Millisecond})
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, 100*time.Millisecond, cfg.DialTimeout)
}
