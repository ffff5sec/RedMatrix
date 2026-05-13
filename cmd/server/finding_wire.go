// finding_wire.go 装配 FindingService（PR-S26）。
package main

import (
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/finding/v1/findingv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/finding"
	findinghandler "github.com/ffff5sec/RedMatrix/internal/finding/handler"
	findingrepo "github.com/ffff5sec/RedMatrix/internal/finding/repo"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

type findingMount struct {
	path    string
	handler http.Handler
}

// buildFindingMount 装配 FindingService。返回 mount + svc（供 scan hook composite 用）。
func buildFindingMount(pool *pg.Pool, authSvc auth.Service, auditHook audithook.Hook) (*findingMount, finding.Service, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildFindingMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildFindingMount: authSvc 不能为 nil")
	}
	findings := findingrepo.NewFindingPG(pool.App)
	events := findingrepo.NewEventPG(pool.App)

	svc, err := finding.New(finding.Deps{Findings: findings, Events: events})
	if err != nil {
		return nil, nil, err
	}

	memberDB := tenancyrepo.NewProjectMemberPG(pool.App)
	h, err := findinghandler.New(svc, authSvc, memberDB)
	if err != nil {
		return nil, nil, err
	}
	if auditHook != nil {
		h.WithAudit(auditHook)
	}
	path, hh := findingv1connect.NewFindingServiceHandler(h)
	return &findingMount{path: path, handler: hh}, svc, nil
}
