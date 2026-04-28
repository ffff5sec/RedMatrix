package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === Aggregator 基础 ===

func TestNewDefaultsTimeout(t *testing.T) {
	a := New(0)
	assert.NotNil(t, a)
	assert.Equal(t, 3*time.Second, a.perProbeTimeout)

	a2 := New(-5 * time.Second)
	assert.Equal(t, 3*time.Second, a2.perProbeTimeout, "负值也走默认")
}

func TestNewExplicitTimeout(t *testing.T) {
	a := New(500 * time.Millisecond)
	assert.Equal(t, 500*time.Millisecond, a.perProbeTimeout)
}

func TestRegisterReplaces(t *testing.T) {
	a := New(time.Second)
	a.Register("p", func(context.Context) error { return errors.New("v1") })
	a.Register("p", func(context.Context) error { return nil })

	rep := a.Check(context.Background())
	require.Contains(t, rep.Checks, "p")
	assert.True(t, rep.Checks["p"].OK)
}

func TestRegisterIgnoresEmptyName(t *testing.T) {
	a := New(time.Second)
	a.Register("", func(context.Context) error { return nil })
	assert.Empty(t, a.Names())
}

func TestRegisterIgnoresNil(t *testing.T) {
	a := New(time.Second)
	a.Register("p", nil)
	assert.Empty(t, a.Names())
}

func TestNamesSorted(t *testing.T) {
	a := New(time.Second)
	a.Register("c", okProbe)
	a.Register("a", okProbe)
	a.Register("b", okProbe)
	assert.Equal(t, []string{"a", "b", "c"}, a.Names())
}

// === Check 行为 ===

func TestCheck_AllPass(t *testing.T) {
	a := New(time.Second)
	a.Register("pg", okProbe)
	a.Register("redis", okProbe)

	rep := a.Check(context.Background())
	assert.Equal(t, StatusOK, rep.Status)
	assert.Len(t, rep.Checks, 2)
	for _, r := range rep.Checks {
		assert.True(t, r.OK)
		assert.Empty(t, r.Error)
	}
}

func TestCheck_OneFails(t *testing.T) {
	a := New(time.Second)
	a.Register("pg", okProbe)
	a.Register("redis", failProbe("boom"))

	rep := a.Check(context.Background())
	assert.Equal(t, StatusDegraded, rep.Status)
	assert.True(t, rep.Checks["pg"].OK)
	assert.False(t, rep.Checks["redis"].OK)
	assert.Equal(t, "boom", rep.Checks["redis"].Error)
}

func TestCheck_AllFail(t *testing.T) {
	a := New(time.Second)
	a.Register("a", failProbe("a-down"))
	a.Register("b", failProbe("b-down"))

	rep := a.Check(context.Background())
	assert.Equal(t, StatusDegraded, rep.Status)
}

func TestCheck_NoProbes(t *testing.T) {
	a := New(time.Second)
	rep := a.Check(context.Background())
	assert.Equal(t, StatusOK, rep.Status, "0 probes = trivially ok")
	assert.Empty(t, rep.Checks)
}

func TestCheck_PerProbeTimeout(t *testing.T) {
	// 慢 probe 应被 perProbeTimeout 中断。
	a := New(50 * time.Millisecond)
	a.Register("slow", func(ctx context.Context) error {
		select {
		case <-time.After(500 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	rep := a.Check(context.Background())
	assert.Equal(t, StatusDegraded, rep.Status)
	assert.False(t, rep.Checks["slow"].OK)
	assert.Less(t, rep.Checks["slow"].DurationMs, int64(200),
		"应 < perProbeTimeout 远早于 500ms")
}

func TestCheck_RunsConcurrently(t *testing.T) {
	// 5 个 probe 各 100ms，并发 → 总耗时应远 < 500ms。
	a := New(time.Second)
	for i := 0; i < 5; i++ {
		a.Register(string(rune('a'+i)), func(ctx context.Context) error {
			time.Sleep(100 * time.Millisecond)
			return nil
		})
	}
	t0 := time.Now()
	rep := a.Check(context.Background())
	elapsed := time.Since(t0)
	assert.Equal(t, StatusOK, rep.Status)
	assert.Less(t, elapsed, 300*time.Millisecond,
		"5 probe 并发 100ms 应 < 300ms（顺序则需 500ms）")
}

func TestCheck_DurationRecorded(t *testing.T) {
	a := New(time.Second)
	a.Register("slow", func(_ context.Context) error {
		time.Sleep(20 * time.Millisecond)
		return nil
	})
	rep := a.Check(context.Background())
	assert.GreaterOrEqual(t, rep.Checks["slow"].DurationMs, int64(15))
}

func TestCheck_CallerCtxCanceled(t *testing.T) {
	a := New(time.Second)
	a.Register("p", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rep := a.Check(ctx)
	assert.Equal(t, StatusDegraded, rep.Status)
}

// === ConcurrentRegister + Check race ===

func TestRegisterCheckRaceSafe(t *testing.T) {
	a := New(time.Second)
	var stop atomic.Bool

	go func() {
		i := 0
		for !stop.Load() {
			a.Register("p", okProbe)
			i++
		}
	}()

	for i := 0; i < 10; i++ {
		_ = a.Check(context.Background())
	}
	stop.Store(true)
	// race detector 必须干净（go test -race）
}

// === Liveness handler ===

func TestLivenessHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	LivenessHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "ok", body["status"])
}

func TestLivenessHandler_AlwaysOK(t *testing.T) {
	// 无论方法 / 路径，liveness 总返 200（kubelet 可能用任意方法探测）。
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(m, "/health", nil)
		LivenessHandler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "method=%s", m)
	}
}

// === Readiness handler ===

func TestReadinessHandler_OK(t *testing.T) {
	a := New(time.Second)
	a.Register("pg", okProbe)
	a.Register("redis", okProbe)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	a.ReadinessHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var rep Report
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rep))
	assert.Equal(t, StatusOK, rep.Status)
	assert.Len(t, rep.Checks, 2)
	assert.GreaterOrEqual(t, rep.DurationMs, int64(0))
}

func TestReadinessHandler_Degraded(t *testing.T) {
	a := New(time.Second)
	a.Register("pg", okProbe)
	a.Register("redis", failProbe("conn refused"))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	a.ReadinessHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var rep Report
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rep))
	assert.Equal(t, StatusDegraded, rep.Status)
	assert.False(t, rep.Checks["redis"].OK)
	assert.Equal(t, "conn refused", rep.Checks["redis"].Error)
}

func TestReadinessHandler_NoProbes(t *testing.T) {
	a := New(time.Second)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	a.ReadinessHandler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "0 probe = OK（trivial）")
}

func TestReadinessHandler_RespectsRequestCtx(t *testing.T) {
	a := New(10 * time.Second)
	a.Register("slow", func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/ready", nil)

	t0 := time.Now()
	a.ReadinessHandler().ServeHTTP(rec, req)
	elapsed := time.Since(t0)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Less(t, elapsed, 200*time.Millisecond, "应被 request ctx 超时切短")
}

// === 帮助函数 ===

func okProbe(_ context.Context) error { return nil }

func failProbe(msg string) Probe {
	return func(_ context.Context) error { return errors.New(msg) }
}
