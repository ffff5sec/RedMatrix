// asset_wire.go 装配 AssetService（PR-S8）。
//
// AssetService 自身有 ConnectRPC mount（/redmatrix.asset.v1.AssetService）；
// 同时通过 scanAssetAdapter 注入到 scan.Service，让 ReportResults 后
// 同步派生资产视图。
package main

import (
	"context"
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1/assetv1connect"
	"github.com/ffff5sec/RedMatrix/internal/asset"
	assethandler "github.com/ffff5sec/RedMatrix/internal/asset/handler"
	assetrepo "github.com/ffff5sec/RedMatrix/internal/asset/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

type assetMount struct {
	path    string
	handler http.Handler
}

// buildAssetMount 装配 AssetService。返 RPC mount + scan service 用的
// AssetDeriver 适配器。
func buildAssetMount(
	pool *pg.Pool,
	authSvc auth.Service,
	logger *log.Logger,
) (*assetMount, scan.AssetDeriver, scan.AssetReader, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildAssetMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildAssetMount: authSvc 不能为 nil")
	}
	r := assetrepo.NewPG(pool.App)
	// PR-S58: 注入 EventRepository 让 UpsertFromResults 派生 asset_events
	// （SPEC §2.7 资产变更事件流 MVP 一期）。
	er := assetrepo.NewEventPG(pool.App)
	svc, err := asset.NewServiceWithEvents(r, er, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	memberDB := tenancyrepo.NewProjectMemberPG(pool.App)
	h, err := assethandler.New(svc, authSvc, memberDB)
	if err != nil {
		return nil, nil, nil, err
	}
	// PR-S58: handler 注入 EventRepository 提供 ListAssetEvents / GetAssetEvent RPC
	h = h.WithEvents(er)
	path, hh := assetv1connect.NewAssetServiceHandler(h)
	return &assetMount{path: path, handler: hh}, &scanAssetAdapter{svc: svc}, &scanAssetReader{assets: svc}, nil
}

// scanAssetAdapter 把 scan.AssetResultInput 转 asset.ResultInput；
// 让 scan service 不直接 import asset 包，避免循环。
type scanAssetAdapter struct {
	svc asset.Service
}

func (a *scanAssetAdapter) UpsertFromResults(ctx context.Context, items []scan.AssetResultInput) error {
	in := make([]asset.ResultInput, 0, len(items))
	for _, it := range items {
		in = append(in, asset.ResultInput{
			TenantID:  it.TenantID,
			ProjectID: it.ProjectID,
			Kind:      it.Kind,
			Data:      it.Data,
		})
	}
	return a.svc.UpsertFromResults(ctx, in)
}
