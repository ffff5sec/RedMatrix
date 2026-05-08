// Package handler 是 tenancy 模块的 ConnectRPC 适配层。
//
// PR-T2 范围：Project CRUD。复用 identity/handler.RequireAuth + RequireRole
// helper（暂不做包间共享 helper；后续 PR 抽出 platform/auth）。
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

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
//
// 按角色过滤（PR-T3 起）：
//   - SA / TenantAuditor：跨项目可见，无 MemberUserID 注入
//   - ProjectAdmin：仅看自己加入的项目（service 注 MemberUserID=principal.UserID）
//   - 其他：拒（暂不开放）
func (h *Handler) ListProjects(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListProjectsRequest],
) (*connect.Response[tenancyv1.ListProjectsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	memberUserID := ""
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RoleTenantAuditor:
		// 全可见
	case identitydomain.RoleProjectAdmin:
		memberUserID = p.UserID
	default:
		return nil, toConnectError(errx.New(errx.ErrAuthzRoleInsufficient,
			"无权列项目").WithFields("role", string(p.Role)))
	}

	in := req.Msg
	out, err := h.svc.ListProjects(ctx, tenancy.ListProjectsRequest{
		TenantID:     in.GetTenantId(),
		Status:       tenancydomain.ProjectStatus(in.GetStatus()),
		Keyword:      in.GetKeyword(),
		Page:         int(in.GetPage()),
		PageSize:     int(in.GetPageSize()),
		MemberUserID: memberUserID,
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

// === ProjectMember ===

func (h *Handler) AddProjectMember(
	ctx context.Context,
	req *connect.Request[tenancyv1.AddProjectMemberRequest],
) (*connect.Response[tenancyv1.AddProjectMemberResponse], error) {
	p, err := h.requireSA(ctx, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.AddProjectMember(ctx, tenancy.AddProjectMemberRequest{
		ProjectID: req.Msg.GetProjectId(),
		UserID:    req.Msg.GetUserId(),
		AddedBy:   p.UserID,
	}); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.AddProjectMemberResponse{}), nil
}

func (h *Handler) RemoveProjectMember(
	ctx context.Context,
	req *connect.Request[tenancyv1.RemoveProjectMemberRequest],
) (*connect.Response[tenancyv1.RemoveProjectMemberResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.RemoveProjectMember(ctx,
		req.Msg.GetProjectId(), req.Msg.GetUserId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.RemoveProjectMemberResponse{}), nil
}

// ListProjectMembers：SA 全可见；该项目的 PA member 也可读；其他拒。
func (h *Handler) ListProjectMembers(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListProjectMembersRequest],
) (*connect.Response[tenancyv1.ListProjectMembersResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}

	projectID := req.Msg.GetProjectId()

	// SA / TA：直放；其他角色（PA）必须先确认自己是该项目成员
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RoleTenantAuditor:
		// ok
	case identitydomain.RoleProjectAdmin:
		// 拉自己加入项目集合判定
		req2 := tenancy.ListProjectsRequest{MemberUserID: p.UserID}
		mine, err := h.svc.ListProjects(ctx, req2)
		if err != nil {
			return nil, toConnectError(err)
		}
		ok := false
		for _, mp := range mine.Projects {
			if mp.ID == projectID {
				ok = true
				break
			}
		}
		if !ok {
			return nil, toConnectError(errx.New(errx.ErrAuthzNotProjectMember,
				"非项目成员").WithFields("project_id", projectID))
		}
	default:
		return nil, toConnectError(errx.New(errx.ErrAuthzRoleInsufficient,
			"无权列项目成员").WithFields("role", string(p.Role)))
	}

	out, err := h.svc.ListProjectMembers(ctx, projectID)
	if err != nil {
		return nil, toConnectError(err)
	}
	pbList := make([]*tenancyv1.ProjectMember, 0, len(out))
	for _, m := range out {
		pbList = append(pbList, memberToProto(m))
	}
	return connect.NewResponse(&tenancyv1.ListProjectMembersResponse{Members: pbList}), nil
}

// === Node ===

func (h *Handler) CreateNode(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateNodeRequest],
) (*connect.Response[tenancyv1.CreateNodeResponse], error) {
	p, err := h.requireSA(ctx, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	tenantID := req.Msg.GetTenantId()
	if tenantID == "" {
		tenantID = p.TenantID
	}
	out, err := h.svc.CreateNode(ctx, tenancy.CreateNodeRequest{
		TenantID:     tenantID,
		Name:         req.Msg.GetName(),
		Version:      req.Msg.GetVersion(),
		Capabilities: req.Msg.GetCapabilities(),
		CreatedBy:    p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateNodeResponse{Node: nodeToProto(out)}), nil
}

func (h *Handler) ListNodes(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListNodesRequest],
) (*connect.Response[tenancyv1.ListNodesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	out, err := h.svc.ListNodes(ctx, tenancy.ListNodesRequest{
		TenantID: in.GetTenantId(),
		Status:   tenancydomain.NodeStatus(in.GetStatus()),
		Keyword:  in.GetKeyword(),
		Page:     int(in.GetPage()),
		PageSize: int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pbList := make([]*tenancyv1.Node, 0, len(out.Nodes))
	for _, n := range out.Nodes {
		pbList = append(pbList, nodeToProto(n))
	}
	//nolint:gosec // total/page/pagesize 经分页钳制，溢出 int32 不可能
	return connect.NewResponse(&tenancyv1.ListNodesResponse{
		Nodes:    pbList,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetNode(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetNodeRequest],
) (*connect.Response[tenancyv1.GetNodeResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		return nil, toConnectError(err)
	}
	out, err := h.svc.GetNode(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.GetNodeResponse{Node: nodeToProto(out)}), nil
}

func (h *Handler) EnableNode(
	ctx context.Context,
	req *connect.Request[tenancyv1.EnableNodeRequest],
) (*connect.Response[tenancyv1.EnableNodeResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.EnableNode(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.EnableNodeResponse{}), nil
}

func (h *Handler) DisableNode(
	ctx context.Context,
	req *connect.Request[tenancyv1.DisableNodeRequest],
) (*connect.Response[tenancyv1.DisableNodeResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DisableNode(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.DisableNodeResponse{}), nil
}

func (h *Handler) DeleteNode(
	ctx context.Context,
	req *connect.Request[tenancyv1.DeleteNodeRequest],
) (*connect.Response[tenancyv1.DeleteNodeResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteNode(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.DeleteNodeResponse{}), nil
}

// === Project Allowed Nodes ===
//
// Set: SA 或该项目的 PA 可调；TA 拒（只读）
// Get: SA / TA 直放；PA 必须先确认是该项目成员

func (h *Handler) SetProjectAllowedNodes(
	ctx context.Context,
	req *connect.Request[tenancyv1.SetProjectAllowedNodesRequest],
) (*connect.Response[tenancyv1.SetProjectAllowedNodesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	projectID := req.Msg.GetProjectId()
	if err := h.requireProjectWriter(ctx, p, projectID); err != nil {
		return nil, toConnectError(err)
	}

	if err := h.svc.SetProjectAllowedNodes(ctx, tenancy.SetProjectAllowedNodesRequest{
		ProjectID: projectID,
		NodeIDs:   req.Msg.GetNodeIds(),
		AddedBy:   p.UserID,
	}); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.SetProjectAllowedNodesResponse{}), nil
}

func (h *Handler) GetProjectAllowedNodes(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetProjectAllowedNodesRequest],
) (*connect.Response[tenancyv1.GetProjectAllowedNodesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	projectID := req.Msg.GetProjectId()
	if err := h.requireProjectReader(ctx, p, projectID); err != nil {
		return nil, toConnectError(err)
	}

	got, err := h.svc.GetProjectAllowedNodes(ctx, projectID)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.GetProjectAllowedNodesResponse{
		AllNodes: got.AllNodes,
		NodeIds:  got.NodeIDs,
	}), nil
}

// requireProjectWriter SA 全权；该项目 PA 也允许；TA / 其他拒。
func (h *Handler) requireProjectWriter(ctx context.Context, p *auth.UserPrincipal, projectID string) error {
	switch p.Role {
	case identitydomain.RoleSuperAdmin:
		return nil
	case identitydomain.RoleProjectAdmin:
		return h.assertProjectMember(ctx, p, projectID)
	default:
		return errx.New(errx.ErrAuthzRoleInsufficient,
			"无权设置项目可用节点").WithFields("role", string(p.Role))
	}
}

// requireProjectReader SA / TA 全权；PA 仅自己加入的项目；其他拒。
func (h *Handler) requireProjectReader(ctx context.Context, p *auth.UserPrincipal, projectID string) error {
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RoleTenantAuditor:
		return nil
	case identitydomain.RoleProjectAdmin:
		return h.assertProjectMember(ctx, p, projectID)
	default:
		return errx.New(errx.ErrAuthzRoleInsufficient,
			"无权读项目可用节点").WithFields("role", string(p.Role))
	}
}

// assertProjectMember 调 ListProjects(MemberUserID=p.UserID) 看 projectID 是否在其中。
func (h *Handler) assertProjectMember(ctx context.Context, p *auth.UserPrincipal, projectID string) error {
	mine, err := h.svc.ListProjects(ctx, tenancy.ListProjectsRequest{MemberUserID: p.UserID})
	if err != nil {
		return err
	}
	for _, mp := range mine.Projects {
		if mp.ID == projectID {
			return nil
		}
	}
	return errx.New(errx.ErrAuthzNotProjectMember,
		"非项目成员").WithFields("project_id", projectID)
}

// === RegistrationToken ===

func (h *Handler) CreateRegistrationToken(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateRegistrationTokenRequest],
) (*connect.Response[tenancyv1.CreateRegistrationTokenResponse], error) {
	p, err := h.requireSA(ctx, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	tenantID := req.Msg.GetTenantId()
	if tenantID == "" {
		tenantID = p.TenantID
	}

	res, err := h.svc.CreateRegistrationToken(ctx, tenancy.CreateRegistrationTokenRequest{
		TenantID:  tenantID,
		Name:      req.Msg.GetName(),
		TTL:       time.Duration(req.Msg.GetTtlSeconds()) * time.Second,
		CreatedBy: p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateRegistrationTokenResponse{
		Token:     registrationTokenToProto(res.Token),
		Plaintext: res.Plaintext,
	}), nil
}

func (h *Handler) ListRegistrationTokens(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListRegistrationTokensRequest],
) (*connect.Response[tenancyv1.ListRegistrationTokensResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		return nil, toConnectError(err)
	}
	tenantID := req.Msg.GetTenantId()
	if tenantID == "" {
		tenantID = p.TenantID
	}
	out, err := h.svc.ListRegistrationTokens(ctx, tenantID)
	if err != nil {
		return nil, toConnectError(err)
	}
	pbList := make([]*tenancyv1.RegistrationToken, 0, len(out))
	for _, t := range out {
		pbList = append(pbList, registrationTokenToProto(t))
	}
	return connect.NewResponse(&tenancyv1.ListRegistrationTokensResponse{
		Tokens: pbList,
	}), nil
}

func (h *Handler) RevokeRegistrationToken(
	ctx context.Context,
	req *connect.Request[tenancyv1.RevokeRegistrationTokenRequest],
) (*connect.Response[tenancyv1.RevokeRegistrationTokenResponse], error) {
	if _, err := h.requireSA(ctx, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.RevokeRegistrationToken(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.RevokeRegistrationTokenResponse{}), nil
}

// RedeemRegistrationToken 是公开 RPC（无 auth）；plaintext 自身即认证。
//
// 注意：本 RPC 用于真节点首次连接前换取节点身份；caller 通常是 Agent 而非
// 浏览器。MVP 把它直接挂在 TenancyService 下；生产可拆出独立"接入端点"。
func (h *Handler) RedeemRegistrationToken(
	ctx context.Context,
	req *connect.Request[tenancyv1.RedeemRegistrationTokenRequest],
) (*connect.Response[tenancyv1.RedeemRegistrationTokenResponse], error) {
	res, err := h.svc.RedeemRegistrationToken(ctx, tenancy.RedeemRegistrationTokenRequest{
		Plaintext: req.Msg.GetPlaintext(),
		NodeName:  req.Msg.GetNodeName(),
		Version:   req.Msg.GetVersion(),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	out := &tenancyv1.RedeemRegistrationTokenResponse{
		Node:        nodeToProto(res.Node),
		NodeCertPem: res.NodeCertPEM,
		NodeKeyPem:  res.NodeKeyPEM,
		CaCertPem:   res.CACertPEM,
		Fingerprint: res.Fingerprint,
	}
	if !res.CertExpiresAt.IsZero() {
		out.CertExpiresAt = res.CertExpiresAt.UTC().Format(time.RFC3339)
	}
	return connect.NewResponse(out), nil
}

// ListNodeCertificates（PR-W6 节点详情页；SA / Auditor only）。
func (h *Handler) ListNodeCertificates(
	ctx context.Context,
	req *connect.Request[tenancyv1.ListNodeCertificatesRequest],
) (*connect.Response[tenancyv1.ListNodeCertificatesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, adminAndAuditor...); err != nil {
		return nil, toConnectError(err)
	}
	certs, err := h.svc.ListCertsByNode(ctx, req.Msg.GetNodeId())
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*tenancyv1.NodeCertificate, 0, len(certs))
	for _, c := range certs {
		out = append(out, nodeCertToProto(c))
	}
	return connect.NewResponse(&tenancyv1.ListNodeCertificatesResponse{
		Certificates: out,
	}), nil
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

func nodeToProto(n *tenancydomain.Node) *tenancyv1.Node {
	if n == nil {
		return nil
	}
	// Status 走 DeriveStatus(now)：让"持久化 online + 心跳过期"的行
	// 在读路径自然展示成 offline，无需依赖周期 sweeper。
	displayStatus := n.DeriveStatus(time.Now())
	if displayStatus == "" {
		displayStatus = n.Status
	}
	out := &tenancyv1.Node{
		Id:           n.ID,
		TenantId:     n.TenantID,
		Name:         n.Name,
		Version:      n.Version,
		Capabilities: append([]string(nil), n.Capabilities...),
		Status:       string(displayStatus),
		CreatedBy:    n.CreatedBy,
		CreatedAt:    timestamppb.New(n.CreatedAt),
		UpdatedAt:    timestamppb.New(n.UpdatedAt),
	}
	if n.LastSeenAt != nil {
		out.LastSeenAt = timestamppb.New(*n.LastSeenAt)
	}
	return out
}

func nodeCertToProto(c *tenancydomain.NodeCertificate) *tenancyv1.NodeCertificate {
	if c == nil {
		return nil
	}
	out := &tenancyv1.NodeCertificate{
		Id:            c.ID,
		NodeId:        c.NodeID,
		SerialNumber:  c.SerialNumber,
		Fingerprint:   c.Fingerprint,
		CommonName:    c.CommonName,
		IssuedAt:      timestamppb.New(c.IssuedAt),
		ExpiresAt:     timestamppb.New(c.ExpiresAt),
		IssuedByToken: c.IssuedByToken,
		CreatedAt:     timestamppb.New(c.CreatedAt),
	}
	if c.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*c.RevokedAt)
	}
	return out
}

func registrationTokenToProto(t *tenancydomain.RegistrationToken) *tenancyv1.RegistrationToken {
	if t == nil {
		return nil
	}
	out := &tenancyv1.RegistrationToken{
		Id:        t.ID,
		TenantId:  t.TenantID,
		Name:      t.Name,
		ExpiresAt: timestamppb.New(t.ExpiresAt),
		CreatedBy: t.CreatedBy,
		CreatedAt: timestamppb.New(t.CreatedAt),
	}
	if t.UsedAt != nil {
		out.UsedAt = timestamppb.New(*t.UsedAt)
	}
	if t.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*t.RevokedAt)
	}
	return out
}

func memberToProto(m *tenancydomain.ProjectMember) *tenancyv1.ProjectMember {
	if m == nil {
		return nil
	}
	return &tenancyv1.ProjectMember{
		ProjectId: m.ProjectID,
		UserId:    m.UserID,
		TenantId:  m.TenantID,
		AddedBy:   m.AddedBy,
		AddedAt:   timestamppb.New(m.AddedAt),
	}
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
