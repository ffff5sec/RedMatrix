// Package handler finding 模块的 ConnectRPC 适配（PR-S26）。
//
// RBAC：
//   - SA / PlatformAuditor：跨租户跨项目
//   - TA：本租户跨项目
//   - PA：本租户 + ProjectMember 求交
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	findingv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/finding/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/finding/v1/findingv1connect"
	auditdomain "github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/finding"
	findingdomain "github.com/ffff5sec/RedMatrix/internal/finding/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
)

// MembershipLookup PA 路径专用。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

// Handler 实现 findingv1connect.FindingServiceHandler。
type Handler struct {
	svc      finding.Service
	authSvc  auth.Service
	memberDB MembershipLookup
	audit    audithook.Hook // PR-S35 可空
}

var _ findingv1connect.FindingServiceHandler = (*Handler)(nil)

// allRoles 读路径（List/Get/ListEvents）— 全部 4 个角色。
// 写路径（Transition/Comment/Assign）用 writers（HLD §4.3：Auditor 只读）。
var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RolePlatformAuditor,
	identitydomain.RoleProjectAdmin,
}

// writers PR-S40：写权限组（修改 finding 状态 / 评论 / 改派）。
// SA + PA；Auditor 拒。
var writers = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleProjectAdmin,
}

// New 构造 handler；memberDB 可空（SA-only）。
func New(svc finding.Service, authSvc auth.Service, memberDB MembershipLookup) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "finding.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc, memberDB: memberDB}, nil
}

// WithAudit 注入审计钩子（PR-S35）。
func (h *Handler) WithAudit(a audithook.Hook) *Handler {
	h.audit = a
	return h
}

func (h *Handler) ListFindings(
	ctx context.Context,
	req *connect.Request[findingv1.ListFindingsRequest],
) (*connect.Response[findingv1.ListFindingsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	listReq := finding.ListFindingsRequest{
		ProjectID:   in.GetProjectId(),
		Status:      in.GetStatus(),
		Severity:    in.GetSeverity(),
		AssigneeID:  in.GetAssigneeId(),
		Keyword:     in.GetKeyword(),
		MinSeverity: in.GetMinSeverity(),
		Page:        int(in.GetPage()),
		PageSize:    int(in.GetPageSize()),
	}

	// RBAC：tenant + project scoping
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		// 不限
	case identitydomain.RoleTenantAuditor:
		listReq.TenantID = p.TenantID
	case identitydomain.RoleProjectAdmin:
		listReq.TenantID = p.TenantID
		if h.memberDB == nil {
			return nil, toConnectError(errx.New(errx.ErrInternal, "PA 路径需 memberDB"))
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, toConnectError(err)
		}
		if len(ids) == 0 {
			// 无项目 → 空页
			//nolint:gosec // 整数都是合理大小
			return connect.NewResponse(&findingv1.ListFindingsResponse{
				Page: int32(listReq.Page), PageSize: int32(listReq.PageSize),
			}), nil
		}
		listReq.ProjectIDs = ids
		// 如果用户传了 project_id，需 ∈ ids 否则返空（避免泄露）
		if listReq.ProjectID != "" {
			found := false
			for _, id := range ids {
				if id == listReq.ProjectID {
					found = true
					break
				}
			}
			if !found {
				//nolint:gosec // page / pageSize ≤ 200 经分页钳制；溢出 int32 不可能
				return connect.NewResponse(&findingv1.ListFindingsResponse{
					Page: int32(listReq.Page), PageSize: int32(listReq.PageSize),
				}), nil
			}
		}
	}

	out, err := h.svc.ListFindings(ctx, listReq)
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*findingv1.Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		pb = append(pb, findingToProto(f))
	}
	//nolint:gosec // total / page / pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&findingv1.ListFindingsResponse{
		Findings: pb,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetFinding(
	ctx context.Context,
	req *connect.Request[findingv1.GetFindingRequest],
) (*connect.Response[findingv1.GetFindingResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	f, err := h.assertFindingVisible(ctx, p, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&findingv1.GetFindingResponse{Finding: findingToProto(f)}), nil
}

func (h *Handler) ListEvents(
	ctx context.Context,
	req *connect.Request[findingv1.ListEventsRequest],
) (*connect.Response[findingv1.ListEventsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertFindingVisible(ctx, p, req.Msg.GetFindingId()); err != nil {
		return nil, toConnectError(err)
	}
	events, err := h.svc.ListEvents(ctx, req.Msg.GetFindingId())
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*findingv1.FindingEvent, 0, len(events))
	for _, e := range events {
		pb = append(pb, eventToProto(e))
	}
	return connect.NewResponse(&findingv1.ListEventsResponse{Events: pb}), nil
}

func (h *Handler) Transition(
	ctx context.Context,
	req *connect.Request[findingv1.TransitionRequest],
) (*connect.Response[findingv1.TransitionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 状态转换为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertFindingVisible(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	f, err := h.svc.Transition(ctx, finding.TransitionRequest{
		ID:      req.Msg.GetId(),
		To:      findingdomain.FindingStatus(req.Msg.GetToStatus()),
		ActorID: p.UserID,
		Comment: req.Msg.GetComment(),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	if h.audit != nil {
		_ = h.audit.Log(ctx, audithook.Event{
			Action:        string(auditdomain.ActionFindingTransition),
			ResourceKind:  "finding",
			ResourceID:    f.ID,
			TenantID:      f.TenantID,
			ProjectID:     f.ProjectID,
			ActorUserID:   p.UserID,
			ActorUsername: p.Username,
			Payload: map[string]any{
				"to_status": string(f.Status),
				"comment":   req.Msg.GetComment(),
			},
		})
	}
	return connect.NewResponse(&findingv1.TransitionResponse{Finding: findingToProto(f)}), nil
}

func (h *Handler) Comment(
	ctx context.Context,
	req *connect.Request[findingv1.CommentRequest],
) (*connect.Response[findingv1.CommentResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 评论为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	f, err := h.assertFindingVisible(ctx, p, req.Msg.GetFindingId())
	if err != nil {
		return nil, toConnectError(err)
	}
	ev, err := h.svc.Comment(ctx, finding.CommentRequest{
		FindingID: req.Msg.GetFindingId(),
		ActorID:   p.UserID,
		Body:      req.Msg.GetBody(),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	if h.audit != nil {
		_ = h.audit.Log(ctx, audithook.Event{
			Action:        string(auditdomain.ActionFindingComment),
			ResourceKind:  "finding",
			ResourceID:    f.ID,
			TenantID:      f.TenantID,
			ProjectID:     f.ProjectID,
			ActorUserID:   p.UserID,
			ActorUsername: p.Username,
			Payload:       map[string]any{"event_id": ev.ID, "body_len": len(req.Msg.GetBody())},
		})
	}
	return connect.NewResponse(&findingv1.CommentResponse{Event: eventToProto(ev)}), nil
}

func (h *Handler) Assign(
	ctx context.Context,
	req *connect.Request[findingv1.AssignRequest],
) (*connect.Response[findingv1.AssignResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: Assign 为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertFindingVisible(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	var assignee *string
	if a := req.Msg.GetAssigneeId(); a != "" {
		assignee = &a
	}
	f, err := h.svc.Assign(ctx, finding.AssignRequest{
		ID:         req.Msg.GetId(),
		ActorID:    p.UserID,
		AssigneeID: assignee,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	if h.audit != nil {
		payload := map[string]any{}
		if assignee != nil {
			payload["to_assignee"] = *assignee
		} else {
			payload["to_assignee"] = nil
		}
		_ = h.audit.Log(ctx, audithook.Event{
			Action:        string(auditdomain.ActionFindingAssign),
			ResourceKind:  "finding",
			ResourceID:    f.ID,
			TenantID:      f.TenantID,
			ProjectID:     f.ProjectID,
			ActorUserID:   p.UserID,
			ActorUsername: p.Username,
			Payload:       payload,
		})
	}
	return connect.NewResponse(&findingv1.AssignResponse{Finding: findingToProto(f)}), nil
}

// === BOLA 校验 ===

// assertFindingVisible 取 finding 并校 caller 是否有权访问。
//   - SA / PlatformAuditor：不限
//   - TA：tenant_id == caller.tenant
//   - PA：上 + project_id ∈ memberDB.ListProjectIDsByUser
func (h *Handler) assertFindingVisible(
	ctx context.Context,
	p *auth.UserPrincipal,
	id string,
) (*findingdomain.Finding, error) {
	f, err := h.svc.GetFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return f, nil
	case identitydomain.RoleTenantAuditor:
		if f.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
		}
		return f, nil
	case identitydomain.RoleProjectAdmin:
		if f.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
		}
		if h.memberDB == nil {
			return nil, errx.New(errx.ErrInternal, "PA 路径需 memberDB")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		for _, pid := range ids {
			if pid == f.ProjectID {
				return f, nil
			}
		}
		return nil, errx.New(errx.ErrFindingNotFound, "finding 不存在").WithFields("id", id)
	}
	return nil, errx.New(errx.ErrFindingNotFound, "finding 不存在")
}

// === Proto 互转 ===

func findingToProto(f *findingdomain.Finding) *findingv1.Finding {
	if f == nil {
		return nil
	}
	//nolint:gosec // occurrence_count 极少超 int32 范围
	out := &findingv1.Finding{
		Id:              f.ID,
		TenantId:        f.TenantID,
		ProjectId:       f.ProjectID,
		DedupKey:        f.DedupKey,
		TemplateId:      f.TemplateID,
		Severity:        string(f.Severity),
		Title:           f.Title,
		Host:            f.Host,
		Description:     f.Description,
		Reference:       f.Reference,
		Status:          string(f.Status),
		FirstSeenAt:     timestamppb.New(f.FirstSeenAt),
		LastSeenAt:      timestamppb.New(f.LastSeenAt),
		OccurrenceCount: int32(f.OccurrenceCount),
		CreatedAt:       timestamppb.New(f.CreatedAt),
		UpdatedAt:       timestamppb.New(f.UpdatedAt),
	}
	if f.SourceResultID != nil {
		out.SourceResultId = *f.SourceResultID
	}
	if f.AssetID != nil {
		out.AssetId = *f.AssetID
	}
	if f.AssigneeID != nil {
		out.AssigneeId = *f.AssigneeID
	}
	return out
}

func eventToProto(e *findingdomain.FindingEvent) *findingv1.FindingEvent {
	if e == nil {
		return nil
	}
	out := &findingv1.FindingEvent{
		Id:        e.ID,
		FindingId: e.FindingID,
		Kind:      string(e.Kind),
		Body:      e.Body,
		CreatedAt: timestamppb.New(e.CreatedAt),
	}
	if e.ActorID != nil {
		out.ActorId = *e.ActorID
	}
	if e.FromStatus != nil {
		out.FromStatus = string(*e.FromStatus)
	}
	if e.ToStatus != nil {
		out.ToStatus = string(*e.ToStatus)
	}
	if e.FromAssignee != nil {
		out.FromAssignee = *e.FromAssignee
	}
	if e.ToAssignee != nil {
		out.ToAssignee = *e.ToAssignee
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
