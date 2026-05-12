// notify_sweeper.go 启动 notify 模块的 retry sweeper goroutine（PR-S25）。
//
// 每 NotifySweeperInterval 拉一批 due delivery 同步发送（webhook/email adapter
// 自带超时）。ctx 取消 → 退出。
package main

import (
	"context"
	"errors"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/notify"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// NotifySweeperInterval 两次拉取间隔；与最短 retry backoff（1m）匹配。
const NotifySweeperInterval = 30 * time.Second

// NotifySweeperBatchLimit 单次拉取的 delivery 上限。
const NotifySweeperBatchLimit = 50

// notifySweeper 实现 notify.RunSweeperOnce 的具体类型；这里靠 type assertion 直接调实现。
type notifySweeper interface {
	RunSweeperOnce(ctx context.Context, batchLimit int) (sent, failed int, err error)
}

func startNotifySweeper(ctx context.Context, svc notify.Service, logger *log.Logger) {
	sw, ok := svc.(notifySweeper)
	if !ok {
		if logger != nil {
			logger.Info("notify: service 未实现 RunSweeperOnce，sweeper 不启动")
		}
		return
	}

	ticker := time.NewTicker(NotifySweeperInterval)
	defer ticker.Stop()

	if logger != nil {
		logger.Info("notify: sweeper started",
			"interval", NotifySweeperInterval.String(),
			"batch", NotifySweeperBatchLimit)
	}

	for {
		select {
		case <-ctx.Done():
			if logger != nil {
				logger.Info("notify: sweeper stopped")
			}
			return
		case <-ticker.C:
			sent, failed, err := sw.RunSweeperOnce(ctx, NotifySweeperBatchLimit)
			if err != nil && !errors.Is(err, context.Canceled) && logger != nil {
				logger.LogError(ctx, "notify: sweeper batch failed", err)
			}
			if (sent > 0 || failed > 0) && logger != nil {
				logger.Info("notify: sweeper batch", "sent", sent, "failed", failed)
			}
		}
	}
}
