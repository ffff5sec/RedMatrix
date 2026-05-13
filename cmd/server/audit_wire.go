// audit_wire.go 装配 AuditService（PR-S33）。
package main

import (
	"context"
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/audit/v1/auditv1connect"
	"github.com/ffff5sec/RedMatrix/internal/audit"
	audithandler "github.com/ffff5sec/RedMatrix/internal/audit/handler"
	auditrepo "github.com/ffff5sec/RedMatrix/internal/audit/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
)

type auditMount struct {
	path    string
	handler http.Handler
}

// buildAuditMount 装配 AuditService + 返 service（供 identity hook 注入）。
func buildAuditMount(pool *pg.Pool, authSvc auth.Service, logger *log.Logger) (*auditMount, audit.Service, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildAuditMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildAuditMount: authSvc 不能为 nil")
	}
	r := auditrepo.NewPG(pool.App)
	svc, err := audit.New(r, logger)
	if err != nil {
		return nil, nil, err
	}
	h, err := audithandler.New(svc, authSvc)
	if err != nil {
		return nil, nil, err
	}
	path, hh := auditv1connect.NewAuditServiceHandler(h)
	return &auditMount{path: path, handler: hh}, svc, nil
}

// identityAuditAdapter 适配 audit.Service → identityhandler.AuditLogger。
// 把 identityhandler.AuditEvent（避反向依赖的本地类型）转 audit.LogEvent。
type identityAuditAdapter struct {
	svc audit.Service
}

func (a *identityAuditAdapter) Log(ctx context.Context, ev identityhandler.AuditEvent) error {
	return a.svc.Log(ctx, audit.LogEvent{
		Action:        ev.Action,
		ResourceKind:  ev.ResourceKind,
		ResourceID:    ev.ResourceID,
		TenantID:      ev.TenantID,
		ProjectID:     ev.ProjectID,
		ActorUserID:   ev.ActorUserID,
		ActorUsername: ev.ActorUsername,
		ActorIP:       ev.ActorIP,
		UserAgent:     ev.UserAgent,
		Payload:       ev.Payload,
	})
}

// newIdentityAuditAdapter 工厂。
func newIdentityAuditAdapter(svc audit.Service) identityhandler.AuditLogger {
	return &identityAuditAdapter{svc: svc}
}
