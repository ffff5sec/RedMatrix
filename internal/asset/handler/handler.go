// Package handler 是 asset 模块的 ConnectRPC 适配层（PR-S8）。
package handler

import (
	"context"
	"encoding/json"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	assetv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1/assetv1connect"
	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	assetrepo "github.com/ffff5sec/RedMatrix/internal/asset/repo"
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
	events   assetrepo.EventRepository // PR-S58: 可空（不注入则 ListAssetEvents 返 Unimplemented）
}

var _ assetv1connect.AssetServiceHandler = (*Handler)(nil)

// WithEvents PR-S58：注入 EventRepository 让 ListAssetEvents / GetAssetEvent 可用。
func (h *Handler) WithEvents(er assetrepo.EventRepository) *Handler {
	h.events = er
	return h
}

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
		Kind:       domain.Kind(req.Msg.GetKind()),
		ProjectID:  req.Msg.GetProjectId(),
		Keyword:    req.Msg.GetKeyword(),
		Page:       int(req.Msg.GetPage()),
		PageSize:   int(req.Msg.GetPageSize()),
		MinAgeDays: int(req.Msg.GetMinAgeDays()),
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

// ListAssetEvents PR-S58 资产变更事件流（SPEC §2.7）。
// RBAC scope 注入与 ListAssets 同形（SA/PA-Audit 不限；TA 注 tenant；PA 注
// tenant + 项目列表）。
func (h *Handler) ListAssetEvents(
	ctx context.Context,
	req *connect.Request[assetv1.ListAssetEventsRequest],
) (*connect.Response[assetv1.ListAssetEventsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if h.events == nil {
		return nil, toConnectError(errx.New(errx.ErrNotImplemented,
			"asset_events 未启用（cmd/server 未注入 EventRepository）"))
	}

	f := assetrepo.EventFilter{
		Kind:      domain.EventKind(req.Msg.GetEventKind()),
		AssetID:   req.Msg.GetAssetId(),
		ProjectID: req.Msg.GetProjectId(),
	}
	if t := req.Msg.GetTimeFrom(); t != nil {
		x := t.AsTime()
		f.TimeFrom = &x
	}
	if t := req.Msg.GetTimeTo(); t != nil {
		x := t.AsTime()
		f.TimeTo = &x
	}

	// RBAC scope（与 ListAssets 同模式）
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		// 不限
	case identitydomain.RoleTenantAuditor:
		f.TenantID = p.TenantID
	case identitydomain.RoleProjectAdmin:
		f.TenantID = p.TenantID
		if h.memberDB == nil {
			return nil, toConnectError(errx.New(errx.ErrInternal,
				"asset.ListAssetEvents: PA 模式需 memberDB"))
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, toConnectError(err)
		}
		if ids == nil {
			ids = []string{}
		}
		f.ProjectIDs = ids
	}

	page := assetrepo.Page{Page: int(req.Msg.GetPage()), PageSize: int(req.Msg.GetPageSize())}
	events, total, err := h.events.List(ctx, f, page)
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*assetv1.AssetEvent, 0, len(events))
	for _, e := range events {
		pb = append(pb, eventToProto(e))
	}
	//nolint:gosec // total/page/page_size 受 service normalize；不溢出 int32
	return connect.NewResponse(&assetv1.ListAssetEventsResponse{
		Events:   pb,
		Total:    int32(total),
		Page:     int32(page.Page),
		PageSize: int32(page.PageSize),
	}), nil
}

// GetAssetEvent PR-S58 单条事件详情。
func (h *Handler) GetAssetEvent(
	ctx context.Context,
	req *connect.Request[assetv1.GetAssetEventRequest],
) (*connect.Response[assetv1.GetAssetEventResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if h.events == nil {
		return nil, toConnectError(errx.New(errx.ErrNotImplemented,
			"asset_events 未启用（cmd/server 未注入 EventRepository）"))
	}
	e, err := h.events.GetByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	// BOLA: TA 跨租户 → AssetNotFound；PA 不在项目 → 同
	switch p.Role {
	case identitydomain.RoleTenantAuditor:
		if e.TenantID != p.TenantID {
			return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset_event 不存在"))
		}
	case identitydomain.RoleProjectAdmin:
		if e.TenantID != p.TenantID {
			return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset_event 不存在"))
		}
		if h.memberDB != nil {
			ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
			if err != nil {
				return nil, toConnectError(err)
			}
			ok := false
			for _, pid := range ids {
				if pid == e.ProjectID {
					ok = true
					break
				}
			}
			if !ok {
				return nil, toConnectError(errx.New(errx.ErrAssetNotFound, "asset_event 不存在"))
			}
		}
	default:
		// SA / PlatformAuditor 不限
	}
	return connect.NewResponse(&assetv1.GetAssetEventResponse{Event: eventToProto(e)}), nil
}

// eventToProto 转 proto；payload 序列化成 JSON 字符串。
func eventToProto(e *domain.Event) *assetv1.AssetEvent {
	if e == nil {
		return nil
	}
	payloadJSON := "{}"
	if e.Payload != nil {
		if b, err := json.Marshal(e.Payload); err == nil {
			payloadJSON = string(b)
		}
	}
	out := &assetv1.AssetEvent{
		Id:          e.ID,
		TenantId:    e.TenantID,
		ProjectId:   e.ProjectID,
		EventKind:   string(e.Kind),
		PayloadJson: payloadJSON,
		CreatedAt:   timestamppb.New(e.CreatedAt),
	}
	if e.AssetID != nil {
		out.AssetId = *e.AssetID
	}
	return out
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
