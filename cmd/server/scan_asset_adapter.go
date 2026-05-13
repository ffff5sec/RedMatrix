// scan_asset_adapter.go —— scan.AssetReader 适配（PR-S34）。
//
// 增量套件 cron 触发时，service 调 AssetReader 取 project 内 stale 资产作 targets。
// 直接用 asset.Service.ListAssets(MinAgeDays, ScopedTenantID, ProjectID) 拉。
package main

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/scan"
)

// scanAssetReader 把 asset.Service 适配成 scan.AssetReader。
type scanAssetReader struct {
	assets asset.Service
}

// ListStaleAssetValues 调 asset.Service.ListAssets(MinAgeDays=staleDays, PageSize=limit)。
// SystemPrincipal 路径：不限 tenant（增量 cron 由 server 自动触发；调用方已校项目权属）。
func (r *scanAssetReader) ListStaleAssetValues(ctx context.Context, projectID string, staleDays, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	res, err := r.assets.ListAssets(ctx, asset.ListRequest{
		ProjectID:  projectID,
		MinAgeDays: staleDays,
		Page:       1,
		PageSize:   limit,
		// ScopedTenantID 留空 = SA-like 全租户（cron 触发场景）
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Assets))
	for _, a := range res.Assets {
		out = append(out, a.Value)
	}
	return out, nil
}

// scan.AssetReader 编译期断言。
var _ scan.AssetReader = (*scanAssetReader)(nil)
