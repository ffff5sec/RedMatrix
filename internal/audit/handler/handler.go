// Package handler audit 模块 ConnectRPC 适配（PR-S33）。
// SA only — TA / PA 一律拒。
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/audit/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/audit/v1/auditv1connect"
	"github.com/ffff5sec/RedMatrix/internal/audit"
	auditdomain "github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
)

// Handler 实现 auditv1connect.AuditServiceHandler。
type Handler struct {
	svc     audit.Service
	authSvc auth.Service
}

var _ auditv1connect.AuditServiceHandler = (*Handler)(nil)

var saOnly = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RolePlatformAuditor,
	identitydomain.RoleTenantAuditor,
}

// New 构造 handler。
func New(svc audit.Service, authSvc auth.Service) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "audit.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc}, nil
}

func (h *Handler) ListLogs(
	ctx context.Context,
	req *connect.Request[auditv1.ListLogsRequest],
) (*connect.Response[auditv1.ListLogsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	listReq := audit.ListLogsRequest{
		TenantID:     p.TenantID, // 默认本租户；SA 跨租户后续可加 tenant_id 入参
		ProjectID:    in.GetProjectId(),
		ActorUserID:  in.GetActorUserId(),
		Action:       in.GetAction(),
		ResourceKind: in.GetResourceKind(),
		ResourceID:   in.GetResourceId(),
		Page:         int(in.GetPage()),
		PageSize:     int(in.GetPageSize()),
	}
	if t := in.GetTimeFrom(); t != nil {
		x := t.AsTime()
		listReq.TimeFrom = &x
	}
	if t := in.GetTimeTo(); t != nil {
		x := t.AsTime()
		listReq.TimeTo = &x
	}

	out, err := h.svc.ListLogs(ctx, listReq)
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*auditv1.AuditLog, 0, len(out.Logs))
	for _, l := range out.Logs {
		pb = append(pb, logToProto(l))
	}
	//nolint:gosec // total/page/pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&auditv1.ListLogsResponse{
		Logs:     pb,
		Total:    int32(out.Total),
		Page:     int32(out.Page),
		PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetLog(
	ctx context.Context,
	req *connect.Request[auditv1.GetLogRequest],
) (*connect.Response[auditv1.GetLogResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	row, err := h.svc.GetLog(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	// 同租户校验（TA only 视角）
	if p.Role == identitydomain.RoleTenantAuditor && row.TenantID != p.TenantID {
		return nil, toConnectError(errx.New(errx.ErrAuditLogNotFound, "audit 不存在").
			WithFields("id", req.Msg.GetId()))
	}
	return connect.NewResponse(&auditv1.GetLogResponse{Log: logToProto(row)}), nil
}

func (h *Handler) VerifyChain(
	ctx context.Context,
	req *connect.Request[auditv1.VerifyChainRequest],
) (*connect.Response[auditv1.VerifyChainResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, saOnly...); err != nil {
		return nil, toConnectError(err)
	}
	r := audit.VerifyChainRequest{
		TenantID: p.TenantID,
		Limit:    int(req.Msg.GetLimit()),
	}
	if t := req.Msg.GetTimeFrom(); t != nil {
		r.TimeFrom = t.AsTime()
	}
	if t := req.Msg.GetTimeTo(); t != nil {
		r.TimeTo = t.AsTime()
	}
	res, err := h.svc.VerifyChain(ctx, r)
	if err != nil {
		return nil, toConnectError(err)
	}
	//nolint:gosec // total / break_at_index < limit ≤ 1000；溢出 int32 不可能
	return connect.NewResponse(&auditv1.VerifyChainResponse{
		Ok:           res.OK,
		Total:        int32(res.Total),
		BreakAtIndex: int32(res.BreakAtIndex),
		BreakAtId:    res.BreakAtID,
	}), nil
}

// === conv ===

func logToProto(a *auditdomain.AuditLog) *auditv1.AuditLog {
	if a == nil {
		return nil
	}
	out := &auditv1.AuditLog{
		Id:            a.ID,
		ActorUsername: a.ActorUsername,
		ActorIp:       a.ActorIP,
		UserAgent:     a.UserAgent,
		Action:        string(a.Action),
		ResourceKind:  a.ResourceKind,
		ResourceId:    a.ResourceID,
		TenantId:      a.TenantID,
		PrevHash:      a.PrevHash,
		Hash:          a.Hash,
		CreatedAt:     timestamppb.New(a.CreatedAt),
	}
	if a.ActorUserID != nil {
		out.ActorUserId = *a.ActorUserID
	}
	if a.ProjectID != nil {
		out.ProjectId = *a.ProjectID
	}
	if pb, err := structpb.NewStruct(a.Payload); err == nil {
		out.Payload = pb
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
