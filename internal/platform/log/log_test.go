package log

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
)

// === 构造与基本输出 ===

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.Info("hello", "k", "v")

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "INFO", got["level"])
	assert.Equal(t, "hello", got["msg"])
	assert.Equal(t, "v", got["k"])
}

func TestNewText(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "text", Output: &buf})
	require.NoError(t, err)

	l.Info("hello", "k", "v")
	out := buf.String()
	assert.Contains(t, out, "level=INFO")
	assert.Contains(t, out, "msg=hello")
	assert.Contains(t, out, "k=v")
}

func TestNewDefaultFormat(t *testing.T) {
	// Format 留空 → JSON
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Output: &buf})
	require.NoError(t, err)

	l.Info("x")
	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "x", got["msg"])
}

func TestNewInvalidLevel(t *testing.T) {
	_, err := New(Config{Level: "verbose", Format: "json"})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

func TestNewInvalidFormat(t *testing.T) {
	_, err := New(Config{Level: "info", Format: "yaml"})
	require.Error(t, err)
	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapConfigInvalid, c)
}

// === Level 过滤 ===

func TestLevelFilteringDebugDropped(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.Debug("dropped")
	l.Info("kept")

	out := buf.String()
	assert.NotContains(t, out, "dropped")
	assert.Contains(t, out, "kept")
}

func TestLevelFilteringTraceVisible(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "trace", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.Trace("trace_msg")
	out := buf.String()
	got := parseJSONLine(t, out)
	assert.Equal(t, "trace_msg", got["msg"])
}

func TestLevelWarnAlias(t *testing.T) {
	for _, alias := range []string{"warn", "warning"} {
		var buf bytes.Buffer
		l, err := New(Config{Level: alias, Format: "json", Output: &buf})
		require.NoError(t, err, alias)

		l.Info("filtered")
		l.Warn("emitted")
		assert.NotContains(t, buf.String(), "filtered", alias)
		assert.Contains(t, buf.String(), "emitted", alias)
	}
}

// === ctx 元数据 ===

func TestWithCtxIncludesAllMeta(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	ctx := context.Background()
	ctx = ctxmeta.WithRequestID(ctx, "req_abc")
	ctx = ctxmeta.WithUserID(ctx, "u_1")
	ctx = ctxmeta.WithTenantID(ctx, "t_1")
	ctx = ctxmeta.WithProjectID(ctx, "p_1")
	ctx = ctxmeta.WithRole(ctx, "SuperAdmin")

	l.WithCtx(ctx).Info("hit")

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "req_abc", got["request_id"])
	assert.Equal(t, "u_1", got["user_id"])
	assert.Equal(t, "t_1", got["tenant_id"])
	assert.Equal(t, "p_1", got["project_id"])
	assert.Equal(t, "SuperAdmin", got["role"])
}

func TestWithCtxNoMeta(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.WithCtx(context.Background()).Info("hi")

	got := parseJSONLine(t, buf.String())
	_, ok := got["request_id"]
	assert.False(t, ok, "no request_id should be emitted when ctx is empty")
}

func TestWithCtxNilSafe(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.WithCtx(nil).Info("x") //nolint:staticcheck // 测试 nil ctx 防御
	require.Contains(t, buf.String(), "x")
}

func TestWithRequestIDEmptyIsNoop(t *testing.T) {
	ctx := ctxmeta.WithRequestID(context.Background(), "")
	assert.Equal(t, "", ctxmeta.RequestIDFromContext(ctx))
}

func TestCtxGetters(t *testing.T) {
	ctx := context.Background()
	ctx = ctxmeta.WithRequestID(ctx, "r")
	ctx = ctxmeta.WithUserID(ctx, "u")
	ctx = ctxmeta.WithTenantID(ctx, "t")
	ctx = ctxmeta.WithProjectID(ctx, "p")
	ctx = ctxmeta.WithRole(ctx, "ProjectAdmin")

	assert.Equal(t, "r", ctxmeta.RequestIDFromContext(ctx))
	assert.Equal(t, "u", ctxmeta.UserIDFromContext(ctx))
	assert.Equal(t, "t", ctxmeta.TenantIDFromContext(ctx))
	assert.Equal(t, "p", ctxmeta.ProjectIDFromContext(ctx))
	assert.Equal(t, "ProjectAdmin", ctxmeta.RoleFromContext(ctx))
}

func TestCtxGettersNilCtxSafe(t *testing.T) {
	assert.Equal(t, "", ctxmeta.RequestIDFromContext(nil)) //nolint:staticcheck
}

// === LogError ===

func TestLogErrorExtractsDomainError(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	cause := errors.New("pgx.ErrNoRows")
	de := errx.Internal(errx.ErrDatabase, cause).
		WithFields("asset_id", "ast_xxx", "tenant_id", "t_xxx")

	ctx := ctxmeta.WithRequestID(context.Background(), "req_abc123")
	ctx = ctxmeta.WithUserID(ctx, "u_xxx")

	l.LogError(ctx, "request failed", de)

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "ERROR", got["level"])
	assert.Equal(t, "request failed", got["msg"])
	assert.Equal(t, "DATABASE_ERROR", got["code"])
	assert.Equal(t, "pgx.ErrNoRows", got["cause"])
	assert.Equal(t, "req_abc123", got["request_id"])
	assert.Equal(t, "u_xxx", got["user_id"])

	fields, ok := got["fields"].(map[string]any)
	require.True(t, ok, "fields should be a nested group")
	assert.Equal(t, "ast_xxx", fields["asset_id"])
	assert.Equal(t, "t_xxx", fields["tenant_id"])
}

func TestLogErrorPlainErrorFallback(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.LogError(context.Background(), "boom", errors.New("plain reason"))

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "boom", got["msg"])
	assert.Equal(t, "plain reason", got["error"])
	_, hasCode := got["code"]
	assert.False(t, hasCode)
}

func TestLogErrorNilNoop(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l.LogError(context.Background(), "x", nil)
	assert.Empty(t, buf.String())
}

func TestLogErrorMessageFromDomain(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	de := errx.New(errx.ErrAssetNotFound, "资产不存在")
	l.LogError(context.Background(), "x", de)

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "ASSET_NOT_FOUND", got["code"])
	assert.Equal(t, "资产不存在", got["message"])
}

func TestLogErrorAdditionalArgs(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	de := errx.New(errx.ErrAssetNotFound, "x")
	l.LogError(context.Background(), "boom", de, "extra", "v")

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "v", got["extra"])
}

// === With + Default ===

func TestWith(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(Config{Level: "info", Format: "json", Output: &buf})
	require.NoError(t, err)

	l2 := l.With("module", "asset")
	l2.Info("hit")

	got := parseJSONLine(t, buf.String())
	assert.Equal(t, "asset", got["module"])
}

func TestDefaultIsNotNil(t *testing.T) {
	assert.NotNil(t, Default())
}

func TestNilLoggerSafe(t *testing.T) {
	var l *Logger
	// 不应 panic
	l.Info("x")
	l.Warn("x")
	l.Error("x")
	l.Debug("x")
	l.Trace("x")
	l.LogError(context.Background(), "x", errors.New("y"))
	l.WithCtx(context.Background()).Info("y")
	l.With("k", "v").Info("z")
}

// === helpers ===

func parseJSONLine(t *testing.T, s string) map[string]any {
	t.Helper()
	s = strings.TrimSpace(s)
	if s == "" {
		t.Fatalf("empty log output")
	}
	// 取最后一行（多次 log 时）
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("json parse failed: %v\nline=%q", err, s)
	}
	return m
}
