// Package handler pluginpkg 模块的 ConnectRPC 适配（PR-S28）。
//
// RBAC：
//   - UploadPackage / SetActive / Deprecate / RevokeSigningKey：SA only
//   - ListPackages / GetPackage / ListSigningKeys：任意已认证角色（含 agent mTLS principal）
//   - GetLatestVersion / GetDownloadURL：任意已认证角色（含 agent）
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	pluginv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/pluginpkg/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/pluginpkg/v1/pluginpkgv1connect"
	auditdomain "github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg"
	plugindomain "github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// Handler 实现 PluginPackageServiceHandler。
type Handler struct {
	svc     pluginpkg.Service
	authSvc auth.Service
	audit   audithook.Hook // PR-S35 可空
}

var _ pluginpkgv1connect.PluginPackageServiceHandler = (*Handler)(nil)

var saOnly = []identitydomain.Role{identitydomain.RoleSuperAdmin}
var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RolePlatformAuditor,
	identitydomain.RoleProjectAdmin,
}

// New 构造 handler。
func New(svc pluginpkg.Service, authSvc auth.Service) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "pluginpkg.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc}, nil
}

// WithAudit 注入审计钩子（PR-S35）。
func (h *Handler) WithAudit(a audithook.Hook) *Handler {
	h.audit = a
	return h
}

// === 包管理（SA only）===

func (h *Handler) UploadPackage(
	ctx context.Context,
	req *connect.Request[pluginv1.UploadPackageRequest],
) (*connect.Response[pluginv1.UploadPackageResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	pkg, err := h.svc.UploadPackage(ctx, pluginpkg.UploadRequest{
		Slug:        req.Msg.GetSlug(),
		Version:     req.Msg.GetVersion(),
		Platform:    req.Msg.GetPlatform(),
		Description: req.Msg.GetDescription(),
		Binary:      req.Msg.GetBinary(),
		UploaderID:  p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	if h.audit != nil {
		_ = h.audit.Log(ctx, audithook.Event{
			Action:        string(auditdomain.ActionPluginUploaded),
			ResourceKind:  "plugin_package",
			ResourceID:    pkg.ID,
			TenantID:      p.TenantID,
			ActorUserID:   p.UserID,
			ActorUsername: p.Username,
			Payload: map[string]any{
				"slug":     pkg.Slug,
				"version":  pkg.Version,
				"platform": string(pkg.Platform),
				"size":     pkg.SizeBytes,
				"sha256":   pkg.SHA256,
			},
		})
	}
	return connect.NewResponse(&pluginv1.UploadPackageResponse{Package: pkgToProto(pkg)}), nil
}

func (h *Handler) ListPackages(
	ctx context.Context,
	req *connect.Request[pluginv1.ListPackagesRequest],
) (*connect.Response[pluginv1.ListPackagesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	var active *bool
	if req.Msg.Active != nil {
		v := req.Msg.GetActive()
		active = &v
	}
	out, err := h.svc.ListPackages(ctx, pluginpkg.ListRequest{
		Slug:     req.Msg.GetSlug(),
		Platform: req.Msg.GetPlatform(),
		Active:   active,
		Page:     int(req.Msg.GetPage()),
		PageSize: int(req.Msg.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*pluginv1.PluginPackage, 0, len(out.Packages))
	for _, p := range out.Packages {
		pb = append(pb, pkgToProto(p))
	}
	//nolint:gosec // total / page / pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&pluginv1.ListPackagesResponse{
		Packages: pb,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetPackage(
	ctx context.Context,
	req *connect.Request[pluginv1.GetPackageRequest],
) (*connect.Response[pluginv1.GetPackageResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	pkg, err := h.svc.GetPackage(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.GetPackageResponse{Package: pkgToProto(pkg)}), nil
}

func (h *Handler) SetPackageActive(
	ctx context.Context,
	req *connect.Request[pluginv1.SetPackageActiveRequest],
) (*connect.Response[pluginv1.SetPackageActiveResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.SetActive(ctx, req.Msg.GetId(), req.Msg.GetActive()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.SetPackageActiveResponse{}), nil
}

func (h *Handler) DeprecatePackage(
	ctx context.Context,
	req *connect.Request[pluginv1.DeprecatePackageRequest],
) (*connect.Response[pluginv1.DeprecatePackageResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeprecatePackage(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.DeprecatePackageResponse{}), nil
}

// === Agent 拉取 ===

func (h *Handler) GetLatestVersion(
	ctx context.Context,
	req *connect.Request[pluginv1.GetLatestVersionRequest],
) (*connect.Response[pluginv1.GetLatestVersionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	pkg, err := h.svc.GetLatestVersion(ctx, req.Msg.GetSlug(), req.Msg.GetPlatform())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.GetLatestVersionResponse{Package: pkgToProto(pkg)}), nil
}

func (h *Handler) GetDownloadURL(
	ctx context.Context,
	req *connect.Request[pluginv1.GetDownloadURLRequest],
) (*connect.Response[pluginv1.GetDownloadURLResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	url, expires, err := h.svc.GetDownloadURL(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.GetDownloadURLResponse{
		Url:       url,
		ExpiresAt: timestamppb.New(expires),
	}), nil
}

// === 签名 ===

func (h *Handler) ListSigningKeys(
	ctx context.Context,
	req *connect.Request[pluginv1.ListSigningKeysRequest],
) (*connect.Response[pluginv1.ListSigningKeysResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	keys, err := h.svc.ListSigningKeys(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*pluginv1.SigningKey, 0, len(keys))
	for _, k := range keys {
		pb = append(pb, keyToProto(k))
	}
	return connect.NewResponse(&pluginv1.ListSigningKeysResponse{Keys: pb}), nil
}

func (h *Handler) RevokeSigningKey(
	ctx context.Context,
	req *connect.Request[pluginv1.RevokeSigningKeyRequest],
) (*connect.Response[pluginv1.RevokeSigningKeyResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.RevokeSigningKey(ctx, req.Msg.GetKeyId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&pluginv1.RevokeSigningKeyResponse{}), nil
}

// === Proto 互转 ===

func pkgToProto(p *plugindomain.PluginPackage) *pluginv1.PluginPackage {
	if p == nil {
		return nil
	}
	out := &pluginv1.PluginPackage{
		Id:           p.ID,
		Slug:         p.Slug,
		Version:      p.Version,
		Platform:     string(p.Platform),
		ArtifactKey:  p.ArtifactKey,
		Sha256:       p.SHA256,
		Signature:    p.Signature,
		SigningKeyId: p.SigningKeyID,
		SizeBytes:    p.SizeBytes,
		Description:  p.Description,
		IsActive:     p.IsActive,
		UploadedBy:   p.UploadedBy,
		UploadedAt:   timestamppb.New(p.UploadedAt),
	}
	if p.DeprecatedAt != nil {
		out.DeprecatedAt = timestamppb.New(*p.DeprecatedAt)
	}
	return out
}

func keyToProto(k *plugindomain.SigningKey) *pluginv1.SigningKey {
	if k == nil {
		return nil
	}
	out := &pluginv1.SigningKey{
		Id:          k.ID,
		KeyId:       k.KeyID,
		PublicKey:   k.PublicKey,
		Description: k.Description,
		CreatedAt:   timestamppb.New(k.CreatedAt),
	}
	if k.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*k.RevokedAt)
	}
	return out
}

func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var de *errx.DomainError
	if errors.As(err, &de) {
		return connect.NewError(de.ConnectCode(),
			errors.New(string(de.Code)+": "+de.Message))
	}
	return connect.NewError(connect.CodeInternal, err)
}
