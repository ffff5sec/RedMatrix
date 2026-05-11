// Package metricsscan 是 scan 模块的 Prometheus 指标集中地（PR-S17-OBSV）。
//
// 中期评审 P0-8 修复：之前 /metrics 只暴露 Go runtime + build_info，零业务可观测。
// 本包定义 5 个核心业务 collector，由 cmd/server.metricsReg.MustRegister。
//
// 命名遵循 internal/platform/metrics §命名约定：
//   - 前缀 redmatrix_scan_
//   - counter 以 _total 结尾
//   - gauge / histogram 显式语义后缀
package metricsscan

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/ffff5sec/RedMatrix/internal/platform/metrics"
)

// Collectors 业务指标集合（导出供 cmd/server 注册 + service / scheduler / sweeper 写）。
type Collectors struct {
	TasksCreated      *prometheus.CounterVec // kind
	TasksTerminal     *prometheus.CounterVec // status (completed / failed / canceled)
	SchedulerTriggers prometheus.Counter
	SweeperSwept      prometheus.Counter
	ResultsInserted   prometheus.Counter // server 端 InsertBulk 成功的结果行数
}

// New 构造 + 注册。重复 New 会 panic（Registry 名字冲突）；boot 唯一。
func New(reg *metrics.Registry) *Collectors {
	c := &Collectors{
		TasksCreated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "scan",
			Name:      "tasks_created_total",
			Help:      "已创建 scan_tasks 累计数；按 task.kind 标签拆分。",
		}, []string{"kind"}),
		TasksTerminal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "scan",
			Name:      "tasks_terminal_total",
			Help:      "task 进入终态累计数；按 final status (completed/failed/canceled) 拆。",
		}, []string{"status"}),
		SchedulerTriggers: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "scan",
			Name:      "scheduler_triggers_total",
			Help:      "cron scheduler 触发回调累计数；与 TasksCreated 配对可算 cron-driven 比例。",
		}),
		SweeperSwept: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "scan",
			Name:      "sweeper_swept_total",
			Help:      "sweeper 回收 (标 failed) 的 stale assignment 累计数。",
		}),
		ResultsInserted: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: "scan",
			Name:      "results_inserted_total",
			Help:      "service.ReportResults 成功写 PG 的扫描结果行累计数（不含 ES / asset 失败回滚）。",
		}),
	}
	reg.MustRegister(
		c.TasksCreated,
		c.TasksTerminal,
		c.SchedulerTriggers,
		c.SweeperSwept,
		c.ResultsInserted,
	)
	return c
}

// Noop 当 metrics 模块未启用时返回空 Collectors（所有 Inc 安全 no-op）。
// 业务层只持 *Collectors 引用即可，不需要 nil-check 每个 method。
func Noop() *Collectors {
	return &Collectors{
		TasksCreated:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "noop_tasks_created"}, []string{"kind"}),
		TasksTerminal:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "noop_tasks_terminal"}, []string{"status"}),
		SchedulerTriggers: prometheus.NewCounter(prometheus.CounterOpts{Name: "noop_scheduler_triggers"}),
		SweeperSwept:      prometheus.NewCounter(prometheus.CounterOpts{Name: "noop_sweeper_swept"}),
		ResultsInserted:   prometheus.NewCounter(prometheus.CounterOpts{Name: "noop_results_inserted"}),
	}
}
