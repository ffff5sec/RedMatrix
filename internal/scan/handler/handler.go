// Package handler 是 scan 模块的 ConnectRPC 适配层（PR-S1）。
//
// 复用 identity/handler.RequireAuth + RequireRole；scan 任务需要 SA / TA / PA
// 角色（PA 仅能操作自己加入的项目；MVP 暂不在 service 层强制 PA 限制——
// 后续 PR 加 ProjectMember 校验）。
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	scanv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1/scanv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// Handler 实现 scanv1connect.ScanServiceHandler。
type Handler struct {
	svc     scan.Service
	authSvc auth.Service
}

var _ scanv1connect.ScanServiceHandler = (*Handler)(nil)

// allRoles 接受任何已认证角色（SA / TA / PA / 平台审计）。
var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RoleProjectAdmin,
	identitydomain.RolePlatformAuditor,
}

// New 构造 ScanService handler。
func New(svc scan.Service, authSvc auth.Service) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "scan.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc}, nil
}

func (h *Handler) CreateScanTask(
	ctx context.Context,
	req *connect.Request[scanv1.CreateScanTaskRequest],
) (*connect.Response[scanv1.CreateScanTaskResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	settings := map[string]any{}
	if in.Settings != nil {
		settings = in.Settings.AsMap()
	}
	t, err := h.svc.CreateTask(ctx, scan.CreateTaskRequest{
		TenantID:     p.TenantID,
		ProjectID:    in.GetProjectId(),
		Name:         in.GetName(),
		Kind:         scandomain.TaskKind(in.GetKind()),
		Target:       in.GetTarget(),
		TargetKind:   scandomain.TargetKind(in.GetTargetKind()),
		ScheduleKind: scandomain.ScheduleKind(in.GetScheduleKind()),
		CronExpr:     in.GetCronExpr(),
		Settings:     settings,
		CreatedBy:    p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.CreateScanTaskResponse{Task: taskToProto(t)}), nil
}

func (h *Handler) ListScanTasks(
	ctx context.Context,
	req *connect.Request[scanv1.ListScanTasksRequest],
) (*connect.Response[scanv1.ListScanTasksResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg
	out, err := h.svc.ListTasks(ctx, scan.ListTasksRequest{
		TenantID:  p.TenantID,
		ProjectID: in.GetProjectId(),
		Status:    scandomain.TaskStatus(in.GetStatus()),
		Keyword:   in.GetKeyword(),
		Page:      int(in.GetPage()),
		PageSize:  int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*scanv1.ScanTask, 0, len(out.Tasks))
	for _, t := range out.Tasks {
		pb = append(pb, taskToProto(t))
	}
	//nolint:gosec // 计数 ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&scanv1.ListScanTasksResponse{
		Tasks: pb, Total: int32(out.Total), Page: int32(out.Page), PageSize: int32(out.PageSize),
	}), nil
}

func (h *Handler) GetScanTask(
	ctx context.Context,
	req *connect.Request[scanv1.GetScanTaskRequest],
) (*connect.Response[scanv1.GetScanTaskResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	t, err := h.svc.GetTask(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.GetScanTaskResponse{Task: taskToProto(t)}), nil
}

func (h *Handler) CancelScanTask(
	ctx context.Context,
	req *connect.Request[scanv1.CancelScanTaskRequest],
) (*connect.Response[scanv1.CancelScanTaskResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.CancelTask(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.CancelScanTaskResponse{}), nil
}

func (h *Handler) DeleteScanTask(
	ctx context.Context,
	req *connect.Request[scanv1.DeleteScanTaskRequest],
) (*connect.Response[scanv1.DeleteScanTaskResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// 删任务暂限 SA + TA（PA 不可删别人的任务）
	if err := identityhandler.RequireRole(p,
		identitydomain.RoleSuperAdmin, identitydomain.RoleTenantAuditor); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteTask(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.DeleteScanTaskResponse{}), nil
}

// === conv ===

func taskToProto(t *scandomain.ScanTask) *scanv1.ScanTask {
	if t == nil {
		return nil
	}
	out := &scanv1.ScanTask{
		Id:           t.ID,
		TenantId:     t.TenantID,
		ProjectId:    t.ProjectID,
		Name:         t.Name,
		Kind:         string(t.Kind),
		Target:       t.Target,
		TargetKind:   string(t.TargetKind),
		Status:       string(t.Status),
		ScheduleKind: string(t.ScheduleKind),
		CronExpr:     t.CronExpr,
		CreatedBy:    t.CreatedBy,
		CreatedAt:    timestamppb.New(t.CreatedAt),
		UpdatedAt:    timestamppb.New(t.UpdatedAt),
	}
	if s, err := structpb.NewStruct(t.Settings); err == nil {
		out.Settings = s
	}
	if t.StartedAt != nil {
		out.StartedAt = timestamppb.New(*t.StartedAt)
	}
	if t.FinishedAt != nil {
		out.FinishedAt = timestamppb.New(*t.FinishedAt)
	}
	return out
}

// toConnectError —— 与其他 handler 一致：DomainError → connect.Code 映射。
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
