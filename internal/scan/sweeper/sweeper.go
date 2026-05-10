// Package sweeper 是 scan 模块的派发回收器（PR-S14）。
//
// 周期扫 PG，把 status IN (pulled, running) 且超过 timeout 未上报的
// assignment 标 failed，避免任务在 agent 崩溃 / 失联时永卡 running。
//
// 模型：sweeper 不直接读写 PG；调 scan.Service.SweepStaleAssignments，
// service 层做"列 stale → UpdateStatus → 触发 task 聚合"。
package sweeper

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// SweepCaller 仅引 scan.Service 的 SweepStaleAssignments 方法子集；
// 让 sweeper 可独立测试不依赖整个 Service。
type SweepCaller interface {
	SweepStaleAssignments(ctx context.Context, timeout time.Duration) (int, error)
}

// 默认值。
const (
	DefaultInterval = 30 * time.Second
	DefaultTimeout  = 10 * time.Minute
)

// Sweeper 周期扫死任务回收器。
type Sweeper struct {
	svc      SweepCaller
	interval time.Duration
	timeout  time.Duration
	logger   *log.Logger
}

// New 构造；svc 不可空，interval/timeout 0 → 默认值；logger 可空。
func New(svc SweepCaller, interval, timeout time.Duration, logger *log.Logger) *Sweeper {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Sweeper{
		svc:      svc,
		interval: interval,
		timeout:  timeout,
		logger:   logger,
	}
}

// Run 阻塞直到 ctx 取消；每 interval 调一次 SweepStaleAssignments。
// 首次启动后立即扫一遍（处理重启时已 stale 的派发）。
func (s *Sweeper) Run(ctx context.Context) error {
	if s == nil || s.svc == nil {
		return nil
	}
	s.tick(ctx)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Sweeper) tick(ctx context.Context) {
	swept, err := s.svc.SweepStaleAssignments(ctx, s.timeout)
	if err != nil && s.logger != nil {
		s.logger.LogError(ctx, "sweep: tick failed", err)
		return
	}
	if swept > 0 && s.logger != nil {
		s.logger.Info("sweep: tick swept", "count", swept, "timeout", s.timeout.String())
	}
}
