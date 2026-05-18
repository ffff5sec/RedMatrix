// scan_continuous_sweeper.go 启动 scan 模块的 continuous 模式回收器（PR-S76）。
//
// 每 ContinuousSweepInterval 调一次 scan.Service.SweepContinuousTasks，
// 把 next_continuous_at ≤ now 的 task clone 出 immediate 实例继续循环。
package main

import (
	"context"
	"errors"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
)

// ContinuousSweepInterval continuous task 拉取周期。SPEC §2.6 「结束 + N 小时」
// 粒度通常以小时计，1 min 拉一次足够及时。
const ContinuousSweepInterval = 1 * time.Minute

// continuousSweepCaller scan.Service 的最小子集。
type continuousSweepCaller interface {
	SweepContinuousTasks(ctx context.Context) (int, error)
}

func startContinuousSweeper(ctx context.Context, svc scan.Service, logger *log.Logger) {
	caller, ok := svc.(continuousSweepCaller)
	if !ok {
		if logger != nil {
			logger.Info("scan continuous sweeper: service 未实现，跳过")
		}
		return
	}
	tick := func() {
		n, err := caller.SweepContinuousTasks(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && logger != nil {
			logger.LogError(ctx, "scan continuous: tick failed", err)
		}
		if n > 0 && logger != nil {
			logger.Info("scan continuous: cloned", "count", n)
		}
	}
	tick() // 启动后立即扫一遍

	t := time.NewTicker(ContinuousSweepInterval)
	defer t.Stop()
	if logger != nil {
		logger.Info("scan continuous sweeper started", "interval", ContinuousSweepInterval.String())
	}
	for {
		select {
		case <-ctx.Done():
			if logger != nil {
				logger.Info("scan continuous sweeper stopped")
			}
			return
		case <-t.C:
			tick()
		}
	}
}
