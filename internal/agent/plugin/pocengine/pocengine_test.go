package pocengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_LoadsEmbeddedTemplates(t *testing.T) {
	p, err := New()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(p.Templates()), 3, "≥ 3 个内嵌模板")
}

func TestKindAndMockFlags(t *testing.T) {
	p, _ := New()
	assert.Equal(t, "vuln_scan", p.Kind())
	assert.False(t, p.IsMock())
}

func TestRun_HitsServerStatusOnRealHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Apache Server Status for localhost\nServer uptime: 1 day"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, err := New()
	require.NoError(t, err)
	results, err := p.Run(context.Background(), srv.URL, "url", nil)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// 至少有一条是 server-status
	found := false
	for _, r := range results {
		if r["template_id"] == "apache-server-status-exposed" {
			found = true
			assert.Equal(t, "redmatrix-poc", r["engine"])
			info, _ := r["info"].(map[string]any)
			assert.Equal(t, "low", info["severity"])
			break
		}
	}
	assert.True(t, found, "应命中 server-status template")
}

func TestRun_CIDRRejected(t *testing.T) {
	p, _ := New()
	_, err := p.Run(context.Background(), "10.0.0.0/24", "cidr", nil)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "cidr"))
}

func TestRun_NoHits_EmptyResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, _ := New()
	results, err := p.Run(context.Background(), srv.URL, "url", nil)
	require.NoError(t, err)
	assert.Empty(t, results)
}
