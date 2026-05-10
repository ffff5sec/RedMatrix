// Package handler 是 asset 模块的 ConnectRPC 适配层（PR-S8）。
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	assetv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1/assetv1connect"
	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
)

// MembershipLookup PA 路径用：与 scan handler 同形。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

// Handler 实现 assetv1connect.AssetServiceHandler。
type Handler struct {
	svc      asset.Service
	authSvc  auth.Service
	memberDB MembershipLookup
}

var _ assetv1connect.AssetServiceHandler = (*Handler)(nil)

var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RoleProjectAdmin,
	identitydomain.RolePlatformAuditor,
}

// New 构造。
func New(svc asset.Service, authSvc auth.Service, memberDB MembershipLookup) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "asset.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc, memberDB: memberDB}, nil
}

func (h *Handler) ListAssets(
	ctx context.Context,
	req *connect.Request[assetv1.ListAssetsRequest],
) (*connect.Response[assetv1.ListAssetsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}

	r := asset.ListRequest{
		Kind:      domain.Kind(req.Msg.GetKind()),
		ProjectID: req.Msg.GetProjectId(),
		Keyword:   req.Msg.GetKeyword(),
		Page:      int(req.Msg.GetPage()),
		PageSize:  int(req.Msg.GetPageSize()),
	}

	// RBAC（与 scan SearchResults 同形）
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		// 不限
	case identitydomain.RoleTenantAuditor:
		r.ScopedTenantID = p.TenantID
	case identitydomain.RoleProjectAdmin:
		r.ScopedTenantID = p.TenantID
		if h.memberDB == nil {
			return nil, toConnectError(errx.New(errx.ErrInternal,
				"asset.ListAssets: PA 模式需 memberDB"))
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, toConnectError(err)
		}
		if ids == nil {
			ids = []string{}
		}
		r.ScopedProjectIDs = ids
	}

	out, err := h.svc.ListAssets(ctx, r)
	if err != nil {
		return nil, toConnectError(err)
	}
	pbAssets := make([]*assetv1.Asset, 0, len(out.Assets))
	for _, a := range out.Assets {
		pbAssets = append(pbAssets, assetToProto(a))
	}
	//nolint:gosec // total/page/page_size 上限受 service normalize；不会溢出 int32
	return connect.NewResponse(&assetv1.ListAssetsResponse{
		Assets:   pbAssets,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetAsset(
	ctx context.Context,
	req *connect.Request[assetv1.GetAssetRequest],
) (*connect.Response[assetv1.GetAssetResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	a, err := h.svc.GetAsset(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	// 简单的 RBAC 收紧：TA 必须同 tenant；PA 必须 join 该项目；SA 不限。
	switch p.Role {
	case identitydomain.RoleTenantAuditor:
		if a.TenantID != p.TenantID {
			return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset 不存在"))
		}
	case identitydomain.RoleProjectAdmin:
		if a.TenantID != p.TenantID {
			return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset 不存在"))
		}
		if h.memberDB != nil {
			ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
			if err != nil {
				return nil, toConnectError(err)
			}
			ok := false
			for _, pid := range ids {
				if pid == a.ProjectID {
					ok = true
					break
				}
			}
			if !ok {
				return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset 不存在"))
			}
		}
	default:
		// SA / PlatformAuditor 不限
	}
	return connect.NewResponse(&assetv1.GetAssetResponse{Asset: assetToProto(a)}), nil
}

func assetToProto(a *domain.Asset) *assetv1.Asset {
	if a == nil {
		return nil
	}
	//nolint:gosec // result_count 上限受业务行为；MVP 单资产 < 1e6
	return &assetv1.Asset{
		Id:          a.ID,
		TenantId:    a.TenantID,
		ProjectId:   a.ProjectID,
		Kind:        string(a.Kind),
		Value:       a.Value,
		FirstSeen:   timestamppb.New(a.FirstSeen),
		LastSeen:    timestamppb.New(a.LastSeen),
		ResultCount: int32(a.ResultCount),
	}
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
