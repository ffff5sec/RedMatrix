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
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
)

// NodeAgentHandler 实现 NodeAgentServiceHandler。
type NodeAgentHandler struct {
	svc tenancy.Service
}

var _ tenancyv1connect.NodeAgentServiceHandler = (*NodeAgentHandler)(nil)

// NewNodeAgent 构造 NodeAgentService handler。
func NewNodeAgent(svc tenancy.Service) (*NodeAgentHandler, error) {
	if svc == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.handler.NewNodeAgent: svc 不能为 nil")
	}
	return &NodeAgentHandler{svc: svc}, nil
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
