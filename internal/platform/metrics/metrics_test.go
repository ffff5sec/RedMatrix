package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_RegistersDefaults(t *testing.T) {
	r := New("v1.2.3", "abc1234", "2026-04-28T00:00:00Z")
	require.NotNil(t, r)

	body := scrape(t, r.Handler())

	// Go runtime collector
	assert.Contains(t, body, "go_goroutines")
	// Process collector
	assert.Contains(t, body, "process_resident_memory_bytes")
	// Build info
	assert.Contains(t, body, `redmatrix_build_info{build_date="2026-04-28T00:00:00Z",commit="abc1234",version="v1.2.3"} 1`)
}

func TestMustRegister_BusinessCollector(t *testing.T) {
	r := New("dev", "x", "y")

	custom := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "test_event_total",
		Help:      "test counter",
	})
	r.MustRegister(custom)
	custom.Inc()
	custom.Inc()

	body := scrape(t, r.Handler())
	assert.Contains(t, body, "redmatrix_test_event_total 2")
}

func TestMustRegister_DuplicatePanics(t *testing.T) {
	r := New("dev", "x", "y")

	// build_info 已注册；再注册同 fqName 会 panic
	dup := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "build_info",
			Help:      "dup",
		},
		[]string{"version", "commit", "build_date"},
	)
	assert.Panics(t, func() { r.MustRegister(dup) })
}

func TestHandler_OpenMetricsFormat(t *testing.T) {
	r := New("dev", "x", "y")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "application/openmetrics-text;version=1.0.0,text/plain;q=0.5")
	r.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	// OpenMetrics 必须以 # EOF 结尾
	assert.True(t, strings.HasSuffix(strings.TrimSpace(body), "# EOF"),
		"OpenMetrics output should end with `# EOF`")
}

func TestHandler_PlainTextFormat(t *testing.T) {
	r := New("dev", "x", "y")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	// 不带 Accept → 默认 plain text
	r.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "redmatrix_build_info")
}

func TestInner_Exposed(t *testing.T) {
	r := New("dev", "x", "y")
	assert.NotNil(t, r.Inner())
	assert.Same(t, r.reg, r.Inner())
}

// === nil-safe ===

func TestNilRegistry(t *testing.T) {
	var r *Registry
	assert.Nil(t, r.Inner())

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code, "nil Registry → 404 placeholder")

	// MustRegister on nil 不 panic
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: Namespace, Name: "x_total", Help: "h"})
	r.MustRegister(c)
}

func TestEmptyRegistry(t *testing.T) {
	// reg 为 nil 的边界（不应通过 New 构造，但防御）
	r := &Registry{}
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// === Helpers ===

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	body, err := io.ReadAll(rec.Body)
	require.NoError(t, err)
	return string(body)
}
