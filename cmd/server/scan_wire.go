// scan_wire.go 装配 ScanService（PR-S1 入口）。
//
// 依赖：pgxpool.App + identity Auth Service + tenancy Project repo（仅 GetByID）。
package main

import (
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1/scanv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scanhandler "github.com/ffff5sec/RedMatrix/internal/scan/handler"
	scanrepo "github.com/ffff5sec/RedMatrix/internal/scan/repo"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// scanMount mount 信息（与 identity / tenancy 同形）。
type scanMount struct {
	path    string
	handler http.Handler
}

// buildScanMount 装配 scan stack 并返 ConnectRPC mount。
func buildScanMount(pool *pg.Pool, authSvc auth.Service) (*scanMount, error) {
	if pool == nil || pool.App == nil {
		return nil, errx.New(errx.ErrInternal, "buildScanMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "buildScanMount: authSvc 不能为 nil")
	}
	tasks := scanrepo.NewTaskPG(pool.App)
	projects := tenancyrepo.NewProjectPG(pool.App)
	svc, err := scan.NewService(tasks, projects)
	if err != nil {
		return nil, err
	}
	h, err := scanhandler.New(svc, authSvc)
	if err != nil {
		return nil, err
	}
	path, hh := scanv1connect.NewScanServiceHandler(h)
	return &scanMount{path: path, handler: hh}, nil
}
