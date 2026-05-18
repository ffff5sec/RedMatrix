// fingerprint_wire.go 装配 FingerprintService（PR-S74 内嵌 + 自定义规则 CRUD）。
package main

import (
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/fingerprint/v1/fingerprintv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/fingerprint"
	fphandler "github.com/ffff5sec/RedMatrix/internal/fingerprint/handler"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
)

type fingerprintMount struct {
	path    string
	handler http.Handler
	// matcher 暴露给 scan_wire 用作 FingerprintLib（实现 scan.FingerprintMatcher）。
	matcher *fingerprint.TenantMatcher
}

// buildFingerprintMount 装配 FingerprintService。
// 返 mount + TenantMatcher（scan.service 用来 enrichFingerprintTech）。
func buildFingerprintMount(
	pool *pg.Pool,
	authSvc auth.Service,
	auditHook audithook.Hook,
) (*fingerprintMount, error) {
	if pool == nil || pool.App == nil {
		return nil, errx.New(errx.ErrInternal, "buildFingerprintMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "buildFingerprintMount: authSvc 不能为 nil")
	}
	builtin := fingerprint.Default()
	repo := fingerprint.NewPGRepo(pool.App)
	matcher := fingerprint.NewTenantMatcher(builtin, repo, 0) // 0 → 默认 60s TTL

	h, err := fphandler.New(builtin, repo, authSvc)
	if err != nil {
		return nil, err
	}
	if auditHook != nil {
		h.WithAudit(auditHook)
	}
	h.WithInvalidator(matcher)
	path, hh := fingerprintv1connect.NewFingerprintServiceHandler(h)
	return &fingerprintMount{path: path, handler: hh, matcher: matcher}, nil
}
