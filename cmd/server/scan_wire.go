// scan_wire.go 装配 ScanService（PR-S1 入口）。
//
// 依赖：pgxpool.App + identity Auth Service + tenancy Project repo（仅 GetByID）。
package main

import (
	"context"
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1/scanv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scanhandler "github.com/ffff5sec/RedMatrix/internal/scan/handler"
	"github.com/ffff5sec/RedMatrix/internal/scan/indexer"
	scanrepo "github.com/ffff5sec/RedMatrix/internal/scan/repo"
	"github.com/ffff5sec/RedMatrix/internal/storage/es"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// scanMount mount 信息（与 identity / tenancy 同形）。
type scanMount struct {
	path    string
	handler http.Handler
}

// buildScanMount 装配 scan stack 并返 ConnectRPC mount + service（NodeAgentHandler
// 需要 scanSvc 让 PR-S3 PullTasks / ReportTaskProgress 工作）。
//
// esClient 可空：未装 / 未配 ES 时 indexer 退化成 nil，scan service 就走 PG-only。
// assetDeriver 可空：dev 不挂 asset 模块时 ReportResults 不派生资产。
func buildScanMount(
	ctx context.Context,
	pool *pg.Pool,
	esClient *es.Client,
	authSvc auth.Service,
	assetDeriver scan.AssetDeriver,
	logger *log.Logger,
) (*scanMount, scan.Service, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildScanMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildScanMount: authSvc 不能为 nil")
	}
	tasks := scanrepo.NewTaskPG(pool.App)
	assignments := scanrepo.NewAssignmentPG(pool.App)
	results := scanrepo.NewResultPG(pool.App)
	projects := tenancyrepo.NewProjectPG(pool.App)
	nodes := tenancyrepo.NewNodePG(pool.App)
	allowed := tenancyrepo.NewAllowedNodesPG(pool.App)

	// PR-S6 ES 双写：esClient 为空时 idx 保持 nil，service 自动跳过双写。
	var idx scan.Indexer
	if esClient != nil && esClient.Client != nil {
		i, err := indexer.New(esClient)
		if err != nil {
			return nil, nil, err
		}
		// EnsureTemplate 失败仅日志，不阻断启动（dev / 弱网常见）。
		if err := i.EnsureTemplate(ctx); err != nil {
			if logger != nil {
				logger.LogError(ctx, "scan: ensure ES template failed", err)
			}
		}
		idx = i
	}

	svc, err := scan.NewService(tasks, assignments, results, projects, nodes, allowed, idx, assetDeriver, logger)
	if err != nil {
		return nil, nil, err
	}
	// PR-S7：PA SearchResults 路径要查用户加入的项目；复用 tenancy member repo
	memberDB := tenancyrepo.NewProjectMemberPG(pool.App)
	h, err := scanhandler.New(svc, authSvc, memberDB)
	if err != nil {
		return nil, nil, err
	}
	path, hh := scanv1connect.NewScanServiceHandler(h)
	return &scanMount{path: path, handler: hh}, svc, nil
}
