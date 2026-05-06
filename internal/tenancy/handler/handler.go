// Package handler 是 tenancy 模块的 ConnectRPC 适配层。
//
// PR-T2 范围：Project CRUD。复用 identity/handler.RequireAuth + RequireRole
// helper（暂不做包间共享 helper；后续 PR 抽出 platform/auth）。
package handler

import (
	"context"
	"errors"
	"net/http"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// Handler 实现 tenancyv1connect.TenancyServiceHandler。
type Handler struct {
	svc     tenancy.Service
	authSvc auth.Service // 给 RequireAuth 用
}

var _ tenancyv1connect.TenancyServiceHandler = (*Handler)(nil)

// New 构造 TenancyService handler。
func New(svc tenancy.Service, authSvc auth.Service) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc}, nil
}

// === 共享 ===

// adminOnly：SA only。
var adminOnly = []identitydomain.Role{identitydomain.RoleSuperAdmin}

// adminAndAuditor：SA + TenantAuditor。
var adminAndAuditor = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
}

// requireSA 对 SA-only RPC 的 auth+authz 简写。
func (h *Handler) requireSA(ctx context.Context, header http.Header) (*auth.UserPrincipal, error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, header)
	if err != nil {
		return nil, err
	}
	if err := identityhandler.RequireRole(p, adminOnly...); err != nil {
		return nil, err
	}
	return p, nil
}

// === CreateProject ===

func (h *Handler) CreateProject(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateProjectRequest],
) (*connect.Response[tenancyv1.CreateProjectResponse], error) {
	p, err := h.requireSA(ctx, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg

	// tenant_id：caller 显式给则用；否则用 principal.TenantID（PA 创建项目时
	// 来自其所属租户。SA principal.TenantID 空，必须显式给）。
	tenantID := in.GetTenantId()
	if tenantID == "" {
		tenantID = p.TenantID
	}

	out, err := h.svc.CreateProject(ctx, tenancy.CreateProjectRequest{
		TenantID:    tenantID,
		Name:        in.GetName(),
		Description: in.GetDescription(),
		CreatedBy:   p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateProjectResponse{
		Project: projectToProto(out),
	}), nil
}

// === ListProjects ===

func (h *Handler) ListProjects(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListProjectsRequest],
) (*connect.Response[tenancyv1.ListProjectsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		// PA / 其他角色：MVP 拒；待 PR-T3 ProjectMember 落地后允许 PA 看自己加入的项目
		return nil, toConnectError(err)
	}

	in := req.Msg
	out, err := h.svc.ListProjects(ctx, tenancy.ListProjectsRequest{
		TenantID: in.GetTenantId(),
		Status:   tenancydomain.ProjectStatus(in.GetStatus()),
		Keyword:  in.GetKeyword(),
		Page:     int(in.GetPage()),
		PageSize: int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}

	pbList := make([]*tenancyv1.Project, 0, len(out.Projects))
	for _, p := range out.Projects {
		pbList = append(pbList, projectToProto(p))
	}
	//nolint:gosec // total/page/pagesize 经分页钳制，溢出 int32 不可能
	return connect.NewResponse(&tenancyv1.ListProjectsResponse{
		Projects: pbList,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

// === GetProject ===

func (h *Handler) GetProject(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetProjectRequest],
) (*connect.Response[tenancyv1.GetProjectResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		return nil, toConnectError(err)
	}
	out, err := h.svc.GetProject(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.GetProjectResponse{Project: projectToProto(out)}), nil
}

// === Archive / Unarchive / Delete（SA only）===

func (h *Handler) ArchiveProject(
	ctx context.Context,
	req *connect.Request[tenancyv1.ArchiveProjectRequest],
) (*connect.Response[tenancyv1.ArchiveProjectResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.ArchiveProject(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.ArchiveProjectResponse{}), nil
}

func (h *Handler) UnarchiveProject(
	ctx context.Context,
	req *connect.Request[tenancyv1.UnarchiveProjectRequest],
) (*connect.Response[tenancyv1.UnarchiveProjectResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.UnarchiveProject(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.UnarchiveProjectResponse{}), nil
}

func (h *Handler) DeleteProject(
	ctx context.Context,
	req *connect.Request[tenancyv1.DeleteProjectRequest],
) (*connect.Response[tenancyv1.DeleteProjectResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteProject(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.DeleteProjectResponse{}), nil
}

// === conv ===

func projectToProto(p *tenancydomain.Project) *tenancyv1.Project {
	if p == nil {
		return nil
	}
	out := &tenancyv1.Project{
		Id:          p.ID,
		TenantId:    p.TenantID,
		Name:        p.Name,
		Description: p.Description,
		Status:      string(p.Status),
		CreatedBy:   p.CreatedBy,
		CreatedAt:   timestamppb.New(p.CreatedAt),
		UpdatedAt:   timestamppb.New(p.UpdatedAt),
	}
	if p.ArchivedAt != nil {
		out.ArchivedAt = timestamppb.New(*p.ArchivedAt)
	}
	return out
}

// === error mapping（与 identity/handler 同思路）===

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
