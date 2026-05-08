// node_agent.go 是 NodeAgentService 的 ConnectRPC 适配层（PR-T4-D3）。
//
// 与 TenancyService 不同：
//   - 不挂 identity RequireAuth；身份由 mTLS 中间件按 cert 指纹反查注 ctx
//   - mount 路径绑独立 mTLS 端口（cmd/server.buildNodeAgentMount）
package handler

import (
	"context"

	"connectrpc.com/connect"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
)

// NodeAgentHandler 实现 NodeAgentServiceHandler。
type NodeAgentHandler struct {
	svc     tenancy.Service
	scanSvc scan.Service // 可空：scan 模块禁用时降级，PullTasks/ReportTaskProgress 返 NotImplemented
}

var _ tenancyv1connect.NodeAgentServiceHandler = (*NodeAgentHandler)(nil)

// NewNodeAgent 构造 NodeAgentService handler。scanSvc 可空（不影响 Heartbeat / ReissueCert）。
func NewNodeAgent(svc tenancy.Service, scanSvc scan.Service) (*NodeAgentHandler, error) {
	if svc == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.handler.NewNodeAgent: svc 不能为 nil")
	}
	return &NodeAgentHandler{svc: svc, scanSvc: scanSvc}, nil
}

// Heartbeat 上报；node_id 从 ctx 取（mTLS middleware 已注入）。
//
// ctx 没 node_id（中间件未挂 / bypass）→ ErrUnauthenticated 防滥用。
func (h *NodeAgentHandler) Heartbeat(
	ctx context.Context,
	req *connect.Request[tenancyv1.HeartbeatRequest],
) (*connect.Response[tenancyv1.HeartbeatResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}

	res, err := h.svc.Heartbeat(ctx, tenancy.HeartbeatRequest{
		NodeID:  nodeID,
		Version: req.Msg.GetVersion(),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.HeartbeatResponse{
		ServerTime:      res.ServerTime.UTC().Format("2006-01-02T15:04:05Z07:00"),
		IntervalSeconds: int32(res.Interval.Seconds()),
	}), nil
}

// ReissueCert（PR-T4-D5）—— 续期；node_id 同 Heartbeat 由 mTLS 中间件注 ctx。
func (h *NodeAgentHandler) ReissueCert(
	ctx context.Context,
	_ *connect.Request[tenancyv1.ReissueCertRequest],
) (*connect.Response[tenancyv1.ReissueCertResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}
	res, err := h.svc.ReissueCert(ctx, tenancy.ReissueCertRequest{NodeID: nodeID})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.ReissueCertResponse{
		NodeCertPem:   res.CertPEM,
		NodeKeyPem:    res.KeyPEM,
		CaCertPem:     res.CACertPEM,
		Fingerprint:   res.Fingerprint,
		CertExpiresAt: res.CertExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}), nil
}

// PullTasks（PR-S3）—— Agent 拉本节点 assigned 任务（mTLS 身份注 ctx）。
func (h *NodeAgentHandler) PullTasks(
	ctx context.Context,
	_ *connect.Request[tenancyv1.PullTasksRequest],
) (*connect.Response[tenancyv1.PullTasksResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}
	if h.scanSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errx.New(errx.ErrNotImplemented, "scan 模块未启用"))
	}
	pulled, err := h.scanSvc.PullForNode(ctx, nodeID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*tenancyv1.AssignedTask, 0, len(pulled))
	for _, p := range pulled {
		out = append(out, &tenancyv1.AssignedTask{
			AssignmentId: p.AssignmentID,
			TaskId:       p.TaskID,
			ProjectId:    p.ProjectID,
			Kind:         string(p.Kind),
			Target:       p.Target,
			TargetKind:   string(p.TargetKind),
		})
	}
	return connect.NewResponse(&tenancyv1.PullTasksResponse{Tasks: out}), nil
}

// ReportTaskProgress（PR-S3）—— Agent 推任务状态。
func (h *NodeAgentHandler) ReportTaskProgress(
	ctx context.Context,
	req *connect.Request[tenancyv1.ReportTaskProgressRequest],
) (*connect.Response[tenancyv1.ReportTaskProgressResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}
	if h.scanSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errx.New(errx.ErrNotImplemented, "scan 模块未启用"))
	}
	if err := h.scanSvc.UpdateAssignmentProgress(ctx,
		nodeID,
		req.Msg.GetAssignmentId(),
		scandomain.AssignmentStatus(req.Msg.GetStatus()),
		req.Msg.GetError(),
	); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.ReportTaskProgressResponse{}), nil
}
