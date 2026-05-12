// node_agent.go 是 NodeAgentService 的 ConnectRPC 适配层（PR-T4-D3）。
//
// 与 TenancyService 不同：
//   - 不挂 identity RequireAuth；身份由 mTLS 中间件按 cert 指纹反查注 ctx
//   - mount 路径绑独立 mTLS 端口（cmd/server.buildNodeAgentMount）
package handler

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg"
	plugindomain "github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	"github.com/ffff5sec/RedMatrix/internal/scan/artifact"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
)

// NodeAgentHandler 实现 NodeAgentServiceHandler。
type NodeAgentHandler struct {
	svc       tenancy.Service
	scanSvc   scan.Service      // 可空：scan 模块禁用时降级，PullTasks/ReportTaskProgress 返 NotImplemented
	artifacts artifact.Store    // 可空：PR-S16 MinIO artifact；为 nil 时 CreateArtifactUploadURL 返 Unimplemented
	pluginSvc pluginpkg.Service // 可空：PR-S29 puller；为 nil 时 plugin RPC 返 Unimplemented
}

var _ tenancyv1connect.NodeAgentServiceHandler = (*NodeAgentHandler)(nil)

// NewNodeAgent 构造 NodeAgentService handler。scanSvc / artifacts / pluginSvc 可空。
func NewNodeAgent(svc tenancy.Service, scanSvc scan.Service, artifacts artifact.Store, pluginSvc pluginpkg.Service) (*NodeAgentHandler, error) {
	if svc == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.handler.NewNodeAgent: svc 不能为 nil")
	}
	return &NodeAgentHandler{svc: svc, scanSvc: scanSvc, artifacts: artifacts, pluginSvc: pluginSvc}, nil
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
			Targets:      p.Targets, // PR-S22
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

// ReportTaskResults（PR-S5）—— Agent 推扫描结果。
func (h *NodeAgentHandler) ReportTaskResults(
	ctx context.Context,
	req *connect.Request[tenancyv1.ReportTaskResultsRequest],
) (*connect.Response[tenancyv1.ReportTaskResultsResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}
	if h.scanSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errx.New(errx.ErrNotImplemented, "scan 模块未启用"))
	}
	items := make([]scan.ResultItem, 0, len(req.Msg.GetItems()))
	for _, st := range req.Msg.GetItems() {
		items = append(items, scan.ResultItem{Data: st.AsMap()})
	}
	if err := h.scanSvc.ReportResults(ctx, nodeID, req.Msg.GetAssignmentId(), items); err != nil {
		return nil, toConnectError(err)
	}
	//nolint:gosec // items 数量由 agent 控制；MVP 单条上报 < 100
	return connect.NewResponse(&tenancyv1.ReportTaskResultsResponse{
		Inserted: int32(len(items)),
	}), nil
}

// CreateArtifactUploadURL（PR-S16）—— agent 申请预签名 PUT URL。
// tenant_id 从 mTLS node 反查（每个 node 绑 tenant）。
func (h *NodeAgentHandler) CreateArtifactUploadURL(
	ctx context.Context,
	req *connect.Request[tenancyv1.CreateArtifactUploadURLRequest],
) (*connect.Response[tenancyv1.CreateArtifactUploadURLResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "mTLS 中间件未注入 node_id"))
	}
	if h.artifacts == nil {
		return nil, connect.NewError(connect.CodeUnimplemented,
			errx.New(errx.ErrNotImplemented, "artifact store 未配置"))
	}
	node, err := h.svc.GetNode(ctx, nodeID)
	if err != nil {
		return nil, toConnectError(err)
	}
	key := h.artifacts.MakeKey(node.TenantID, req.Msg.GetExt())
	expires := time.Now().Add(artifact.DefaultURLTTL)
	url, err := h.artifacts.PresignPutURL(ctx, key, artifact.DefaultURLTTL)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.CreateArtifactUploadURLResponse{
		Key:       key,
		Url:       url,
		ExpiresAt: timestamppb.New(expires),
	}), nil
}

// === PR-S29 插件包分发（agent puller 走 mTLS）===

// ListPluginSigningKeys 返回所有未撤销公钥。
func (h *NodeAgentHandler) ListPluginSigningKeys(
	ctx context.Context,
	_ *connect.Request[tenancyv1.ListPluginSigningKeysRequest],
) (*connect.Response[tenancyv1.ListPluginSigningKeysResponse], error) {
	if ctxmeta.NodeIDFromContext(ctx) == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errx.New(errx.ErrAuthFailed, "缺 node_id（mTLS 中间件未挂）"))
	}
	if h.pluginSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errx.New(errx.ErrNotImplemented, "plugin puller 未启用"))
	}
	keys, err := h.pluginSvc.ListSigningKeys(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*tenancyv1.PluginSigningKey, 0, len(keys))
	for _, k := range keys {
		pb = append(pb, pluginKeyToAgentProto(k))
	}
	return connect.NewResponse(&tenancyv1.ListPluginSigningKeysResponse{Keys: pb}), nil
}

// GetLatestPluginVersion 拉 (slug, platform) 最新可用包。
func (h *NodeAgentHandler) GetLatestPluginVersion(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetLatestPluginVersionRequest],
) (*connect.Response[tenancyv1.GetLatestPluginVersionResponse], error) {
	if ctxmeta.NodeIDFromContext(ctx) == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errx.New(errx.ErrAuthFailed, "缺 node_id"))
	}
	if h.pluginSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errx.New(errx.ErrNotImplemented, "plugin puller 未启用"))
	}
	pkg, err := h.pluginSvc.GetLatestVersion(ctx, req.Msg.GetSlug(), req.Msg.GetPlatform())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.GetLatestPluginVersionResponse{Package: pluginPkgToAgentProto(pkg)}), nil
}

// GetPluginDownloadURL 生成 presigned GET URL。
func (h *NodeAgentHandler) GetPluginDownloadURL(
	ctx context.Context,
	req *connect.Request[tenancyv1.GetPluginDownloadURLRequest],
) (*connect.Response[tenancyv1.GetPluginDownloadURLResponse], error) {
	if ctxmeta.NodeIDFromContext(ctx) == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errx.New(errx.ErrAuthFailed, "缺 node_id"))
	}
	if h.pluginSvc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errx.New(errx.ErrNotImplemented, "plugin puller 未启用"))
	}
	url, expires, err := h.pluginSvc.GetDownloadURL(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&tenancyv1.GetPluginDownloadURLResponse{
		Url:       url,
		ExpiresAt: timestamppb.New(expires),
	}), nil
}

func pluginKeyToAgentProto(k *plugindomain.SigningKey) *tenancyv1.PluginSigningKey {
	if k == nil {
		return nil
	}
	out := &tenancyv1.PluginSigningKey{
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

func pluginPkgToAgentProto(p *plugindomain.PluginPackage) *tenancyv1.PluginPackageRef {
	if p == nil {
		return nil
	}
	return &tenancyv1.PluginPackageRef{
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
		UploadedAt:   timestamppb.New(p.UploadedAt),
	}
}
