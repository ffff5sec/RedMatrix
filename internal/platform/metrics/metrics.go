// Package metrics 是 RedMatrix 后端 Prometheus 指标的注册门面。
//
// 设计（与 docs/LLD/40-deployment-detail.md §6.2 / 17-monitor-module §10 对齐）：
//   - 单 *prometheus.Registry 集中所有指标；通过 Registry 类型导出
//     有限 API，避免业务直接 import prometheus
//   - 默认注册 Go 运行时（goroutines / GC / heap）+ 进程（CPU / mem / fds）+
//     redmatrix_build_info（version / commit / build_date）
//   - HTTP /metrics 由 Handler() 提供（promhttp，OpenMetrics 协商）
//   - 业务模块自管 collector：定义 → r.MustRegister → Inc/Set/Observe
//
// 命名约定（LLD 40 §6.2）：
//   - 全部以 `redmatrix_` 前缀
//   - counter 以 `_total` 结尾
//   - duration 用 seconds 单位（_seconds 后缀）
//   - bytes 用 _bytes 后缀
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Namespace 是所有 RedMatrix 指标的统一前缀。
const Namespace = "redmatrix"

// Registry 包装 *prometheus.Registry。零值不可用；用 New 构造。
type Registry struct {
	reg *prometheus.Registry
}

// New 创建 Registry 并预注册：
//   - Go 运行时 collector
//   - 进程 collector
//   - build_info gauge（version / commit / build_date 标签）
//
// version / commit / buildDate 来自 internal/version 包；调用方在 cmd/server boot
// 时传入，让 metrics.{version,commit,build_date} 标签反映本进程实际版本。
func New(version, commit, buildDate string) *Registry {
	reg := prometheus.NewRegistry()

	// 默认 Go runtime + process collectors。
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	// build_info：常用 Prometheus 模式 —— 一个永远 = 1 的 gauge，标签里塞版本。
	buildInfo := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "build_info",
			Help:      "RedMatrix build info（永远 = 1）；version / commit / build_date 通过标签暴露。",
		},
		[]string{"version", "commit", "build_date"},
	)
	buildInfo.WithLabelValues(version, commit, buildDate).Set(1)
	reg.MustRegister(buildInfo)

	return &Registry{reg: reg}
}

// MustRegister 把 collector 注册到内部 *prometheus.Registry。重复 Name 会 panic。
// 业务模块在 init / boot 时调用一次即可。
func (r *Registry) MustRegister(cs ...prometheus.Collector) {
	if r == nil || r.reg == nil {
		return
	}
	r.reg.MustRegister(cs...)
}

// Inner 暴露底层 *prometheus.Registry，供需要直接调 prometheus API 的高级用例。
// 业务代码优先用 MustRegister + Handler；Inner 仅给特殊集成。
func (r *Registry) Inner() *prometheus.Registry {
	if r == nil {
		return nil
	}
	return r.reg
}

// Handler 返回 /metrics 的 http.Handler（OpenMetrics + protobuf 协商）。
func (r *Registry) Handler() http.Handler {
	if r == nil || r.reg == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{
		// EnableOpenMetrics 让 Prometheus 服务端用 OpenMetrics 拉（更精确的时间戳）
		EnableOpenMetrics: true,
		// 失败时把错误塞响应（默认行为；显式标记）
		ErrorHandling: promhttp.ContinueOnError,
	})
}
