// Package health 提供 RedMatrix 后端的 /health 与 /ready HTTP endpoint。
//
// 设计（与 docs/LLD/40-deployment-detail.md §6.6 严格对齐）：
//   - /health （liveness）：进程活着即 200。永远不依赖任何外部存储。
//     用于 docker / k8s 的 livenessProbe（避免误杀正在启动的进程）。
//   - /ready  （readiness）：调用 Aggregator 全部 probe，所有通过 → 200，
//     任一失败 → 503。用于 readinessProbe 与负载均衡剔除。
//
// 与各存储 client 的解耦：probe 是 `func(ctx) error` 函数；调用方注册 pg.Pool.Ping /
// redis.Client.Ping / es.Client.Ping / minio.Client.Ping 即可，不依赖具体类型。
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status 取值。
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
)

// Probe 是单个就绪检查。失败时返回 error；error.Error() 会被序列化到响应（不含 cause）。
type Probe func(ctx context.Context) error

// CheckResult 单个 probe 的结果。
type CheckResult struct {
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Report 是 /ready 响应主体。
type Report struct {
	Status     string                 `json:"status"`
	Checks     map[string]CheckResult `json:"checks"`
	DurationMs int64                  `json:"duration_ms"`
}

// Aggregator 持有 N 个命名 probe，并发执行。
type Aggregator struct {
	mu              sync.RWMutex
	probes          map[string]Probe
	perProbeTimeout time.Duration
}

// New 创建 Aggregator。perProbeTimeout ≤ 0 时取默认 3s。
func New(perProbeTimeout time.Duration) *Aggregator {
	if perProbeTimeout <= 0 {
		perProbeTimeout = 3 * time.Second
	}
	return &Aggregator{
		probes:          make(map[string]Probe),
		perProbeTimeout: perProbeTimeout,
	}
}

// Register 注册 probe；同名重复注册会替换（测试便利）。
// name 为空或 probe 为 nil 时静默忽略，避免污染 Aggregator。
func (a *Aggregator) Register(name string, probe Probe) {
	if name == "" || probe == nil {
		return
	}
	a.mu.Lock()
	a.probes[name] = probe
	a.mu.Unlock()
}

// Names 列出所有已注册 probe 名（按字典序）；测试与 /readyz 调试用。
func (a *Aggregator) Names() []string {
	a.mu.RLock()
	out := make([]string, 0, len(a.probes))
	for k := range a.probes {
		out = append(out, k)
	}
	a.mu.RUnlock()
	// stable order — caller may rely on JSON key order tests
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Check 并发执行所有 probe，返回 Report。每个 probe 受 perProbeTimeout 限制。
//
// 如果调用方传入的 ctx 已被取消，Check 立即返回所有 probe 都未跑（status=degraded
// + error="context canceled"），避免误判。
func (a *Aggregator) Check(ctx context.Context) Report {
	a.mu.RLock()
	snapshot := make(map[string]Probe, len(a.probes))
	for name, p := range a.probes {
		snapshot[name] = p
	}
	a.mu.RUnlock()

	started := time.Now()
	results := make(map[string]CheckResult, len(snapshot))
	var resMu sync.Mutex
	var wg sync.WaitGroup

	for name, probe := range snapshot {
		wg.Add(1)
		go func(name string, probe Probe) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, a.perProbeTimeout)
			defer cancel()
			t0 := time.Now()
			err := probe(pctx)
			cr := CheckResult{
				OK:         err == nil,
				DurationMs: time.Since(t0).Milliseconds(),
			}
			if err != nil {
				cr.Error = err.Error()
			}
			resMu.Lock()
			results[name] = cr
			resMu.Unlock()
		}(name, probe)
	}
	wg.Wait()

	status := StatusOK
	for _, r := range results {
		if !r.OK {
			status = StatusDegraded
			break
		}
	}
	return Report{
		Status:     status,
		Checks:     results,
		DurationMs: time.Since(started).Milliseconds(),
	}
}

// LivenessHandler 总是返回 200 OK + {"status":"ok"}。永远不依赖外部存储。
func LivenessHandler() http.Handler {
	body := []byte(`{"status":"ok"}`)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

// ReadinessHandler 跑所有 probe 并以 200 / 503 + JSON Report 响应。
//
// 状态码：
//   - 200 — 全部 probe 通过
//   - 503 — 任一 probe 失败（含 ctx 超时 / 取消）
func (a *Aggregator) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		report := a.Check(r.Context())
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if report.Status == StatusOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		// 序列化失败时连接已半破，无可挽救。
		_ = json.NewEncoder(w).Encode(report)
	})
}
