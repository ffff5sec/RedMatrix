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
	"github.com/ffff5sec/RedMatrix/internal/scan/scheduler"
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
// 需要 scanSvc 让 PR-S3 PullTasks / ReportTaskProgress 工作）+ scheduler
// （main 需 LoadAll + Start + Stop 控生命周期）。
//
// esClient 可空：未装 / 未配 ES 时 indexer 退化成 nil，scan service 就走 PG-only。
// assetDeriver 可空：dev 不挂 asset 模块时 ReportResults 不派生资产。
func buildScanMount(
	ctx context.Context,
	pool *pg.Pool,
	esClient *es.Client,
	authSvc auth.Service,
	assetDeriver scan.AssetDeriver,
	artifactStore scan.ArtifactStore,
	logger *log.Logger,
) (*scanMount, scan.Service, *scheduler.Scheduler, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildScanMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildScanMount: authSvc 不能为 nil")
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
			return nil, nil, nil, err
		}
		// EnsureTemplate 失败仅日志，不阻断启动（dev / 弱网常见）。
		if err := i.EnsureTemplate(ctx); err != nil {
			if logger != nil {
				logger.LogError(ctx, "scan: ensure ES template failed", err)
			}
		}
		idx = i
	}

	// PR-S12 scheduler：late-binding service 引用避循环。
	// trigger 闭包捕获 svcHolder，CreateTask 后再赋值 svc；
	// scheduler.Start 前 LoadAll 时 svcHolder 已 ready。
	var svc scan.Service
	listing := &cronListingAdapter{repo: tasks}
	sched, err := scheduler.New(listing, func(ctx context.Context, taskID string) {
		if svc != nil {
			_ = svc.TriggerCronTask(ctx, taskID)
		}
	}, logger)
	if err != nil {
		return nil, nil, nil, err
	}

	svc, err = scan.NewService(tasks, assignments, results, projects, nodes, allowed, idx, assetDeriver, sched, artifactStore, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	// PR-S7：PA SearchResults 路径要查用户加入的项目；复用 tenancy member repo
	memberDB := tenancyrepo.NewProjectMemberPG(pool.App)
	h, err := scanhandler.New(svc, authSvc, memberDB)
	if err != nil {
		return nil, nil, nil, err
	}
	path, hh := scanv1connect.NewScanServiceHandler(h)
	return &scanMount{path: path, handler: hh}, svc, sched, nil
}

// cronListingAdapter 把 scanrepo.TaskRepository 适配成 scheduler.TaskListing。
// 让 scheduler 包不依赖 scan/repo 类型（保持 scheduler 包薄）。
type cronListingAdapter struct {
	repo scanrepo.TaskRepository
}

func (a *cronListingAdapter) ListCronTemplates(ctx context.Context) ([]scheduler.CronTemplate, error) {
	rows, err := a.repo.ListCronTemplates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]scheduler.CronTemplate, 0, len(rows))
	for _, r := range rows {
		out = append(out, scheduler.CronTemplate{TaskID: r.TaskID, CronExpr: r.CronExpr})
	}
	return out, nil
}
