// asset_sweeper.go 启动 asset 模块的两条 sweeper goroutine（PR-S59）。
//
//   - SweepDisappeared: 把 last_seen 超 AssetDisappearedThreshold 的资产打
//     disappeared_at + 派 asset_disappeared 事件
//   - SweepCertsExpiring: 扫 tls_scan 结果里 not_after 在 CertExpiringWindow
//     内的证书 + 派 cert_expiring_soon 事件
//
// SPEC §2.7 MVP 一期 5 事件的最后两条。ctx 取消 → 退出。
package main

import (
	"context"
	"errors"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// 默认参数；dev / prod 暂不开放 env 覆盖（先打基线）。
const (
	// AssetSweeperInterval 两次扫描间隔；不需太频繁，事件最迟延 1h 体现。
	AssetSweeperInterval = 1 * time.Hour
	// AssetDisappearedThreshold last_seen 老于此值视为消失。
	AssetDisappearedThreshold = 14 * 24 * time.Hour
	// CertExpiringWindow not_after 落在 (now, now+此值] 视为即将到期。
	CertExpiringWindow = 30 * 24 * time.Hour
	// CertExpiringDedupeWindow 同 fingerprint 此时间内不重复派事件。
	CertExpiringDedupeWindow = 7 * 24 * time.Hour
)

func startAssetSweeper(ctx context.Context, svc asset.Service, logger *log.Logger) {
	if svc == nil {
		if logger != nil {
			logger.Info("asset: sweeper 未启动（svc nil）")
		}
		return
	}

	// 启动后立即跑一轮，避免长 interval 下首次到期等太久。
	runAssetSweepOnce(ctx, svc, logger)

	ticker := time.NewTicker(AssetSweeperInterval)
	defer ticker.Stop()

	if logger != nil {
		logger.Info("asset: sweeper started",
			"interval", AssetSweeperInterval.String(),
			"disappeared_threshold", AssetDisappearedThreshold.String(),
			"cert_window", CertExpiringWindow.String())
	}

	for {
		select {
		case <-ctx.Done():
			if logger != nil {
				logger.Info("asset: sweeper stopped")
			}
			return
		case <-ticker.C:
			runAssetSweepOnce(ctx, svc, logger)
		}
	}
}

func runAssetSweepOnce(ctx context.Context, svc asset.Service, logger *log.Logger) {
	if n, err := svc.SweepDisappeared(ctx, AssetDisappearedThreshold); err != nil {
		if !errors.Is(err, context.Canceled) && logger != nil {
			logger.LogError(ctx, "asset: sweep disappeared failed", err)
		}
	} else if n > 0 && logger != nil {
		logger.Info("asset: sweep disappeared", "events", n)
	}
	if n, err := svc.SweepCertsExpiring(ctx, CertExpiringWindow, CertExpiringDedupeWindow); err != nil {
		if !errors.Is(err, context.Canceled) && logger != nil {
			logger.LogError(ctx, "asset: sweep certs expiring failed", err)
		}
	} else if n > 0 && logger != nil {
		logger.Info("asset: sweep certs expiring", "events", n)
	}
}
