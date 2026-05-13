// Package handler notify 模块的 ConnectRPC 适配（PR-S25）。
//
// RBAC：
//   - SA / PlatformAuditor：跨租户
//   - TA：本租户
//   - PA：本租户 + project 必须 ∈ join 项目
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	notifyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/notify/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/notify/v1/notifyv1connect"
	auditdomain "github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/notify"
	notifydomain "github.com/ffff5sec/RedMatrix/internal/notify/domain"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
)

// MembershipLookup PA 路径专用。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

// Handler 实现 notifyv1connect.NotifyServiceHandler。
type Handler struct {
	svc      notify.Service
	authSvc  auth.Service
	memberDB MembershipLookup
	audit    audithook.Hook // PR-S41 可空
}

var _ notifyv1connect.NotifyServiceHandler = (*Handler)(nil)

// WithAudit 注入审计钩子（PR-S41）。
func (h *Handler) WithAudit(a audithook.Hook) *Handler {
	h.audit = a
	return h
}

// logSubAudit PR-S41：订阅 CRUD 通用 audit。
func (h *Handler) logSubAudit(
	ctx context.Context,
	p *auth.UserPrincipal,
	action auditdomain.ActionKind,
	sub *notifydomain.Subscription,
	subID string,
	payload map[string]any,
) {
	if h.audit == nil {
		return
	}
	if payload == nil {
		payload = map[string]any{}
	}
	tenantID := p.TenantID
	if sub != nil && sub.TenantID != "" {
		tenantID = sub.TenantID
	}
	if tenantID == "" {
		tenantID = "00000000-0000-0000-0000-000000000001"
	}
	ev := audithook.Event{
		Action:        string(action),
		ResourceKind:  "notify_subscription",
		ResourceID:    subID,
		TenantID:      tenantID,
		ActorUserID:   p.UserID,
		ActorUsername: p.Username,
		Payload:       payload,
	}
	if sub != nil && sub.ProjectID != nil {
		ev.ProjectID = *sub.ProjectID
	}
	_ = h.audit.Log(ctx, ev)
}

// allRoles 读路径（List/Get/ListDeliveries）— 全部 4 个角色。
// 写路径（Create/Update/Delete/Test）用 writers（HLD §4.3：Auditor 只读）。
var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RolePlatformAuditor,
	identitydomain.RoleProjectAdmin,
}

// writers PR-S40：写权限组（订阅 CRUD + 发测试 webhook）。
// SA + PA；Auditor 拒。TestSubscription 也归此组，
// 因发测试 webhook 会触发外部 HTTP/邮件出站，等价于写操作。
var writers = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleProjectAdmin,
}

// New 构造 handler；memberDB 可空（SA-only 场景）。
func New(svc notify.Service, authSvc auth.Service, memberDB MembershipLookup) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "notify.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc, memberDB: memberDB}, nil
}

// === RPC 实现 ===

func (h *Handler) CreateSubscription(
	ctx context.Context,
	req *connect.Request[notifyv1.CreateSubscriptionRequest],
) (*connect.Response[notifyv1.CreateSubscriptionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 创建订阅为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	if err := h.assertProjectMember(ctx, p, in.GetProjectId()); err != nil {
		return nil, toConnectError(err)
	}

	var projectIDPtr *string
	if pid := in.GetProjectId(); pid != "" {
		projectIDPtr = &pid
	}

	cfg := map[string]any{}
	if in.GetConfig() != nil {
		cfg = in.GetConfig().AsMap()
	}
	filter := map[string]any{}
	if in.GetFilter() != nil {
		filter = in.GetFilter().AsMap()
	}
	kinds := make([]notifydomain.EventKind, 0, len(in.GetEventKinds()))
	for _, k := range in.GetEventKinds() {
		kinds = append(kinds, notifydomain.EventKind(k))
	}

	sub, err := h.svc.CreateSubscription(ctx, notify.CreateSubscriptionRequest{
		TenantID:   p.TenantID,
		ProjectID:  projectIDPtr,
		Name:       in.GetName(),
		EventKinds: kinds,
		Channel:    notifydomain.Channel(in.GetChannel()),
		Config:     cfg,
		Filter:     filter,
		Enabled:    in.GetEnabled(),
		CreatedBy:  p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	h.logSubAudit(ctx, p, auditdomain.ActionNotifySubCreated, sub, sub.ID, map[string]any{
		"name":    sub.Name,
		"channel": string(sub.Channel),
		"enabled": sub.Enabled,
	})
	return connect.NewResponse(&notifyv1.CreateSubscriptionResponse{Subscription: subToProto(sub)}), nil
}

func (h *Handler) ListSubscriptions(
	ctx context.Context,
	req *connect.Request[notifyv1.ListSubscriptionsRequest],
) (*connect.Response[notifyv1.ListSubscriptionsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg

	// SA/PA-Audit 可不限租户，但 MVP 仅用 caller 自己的 tenant；
	// 若需跨租户后续可加 tenant_id 入参显式暴露
	tenantID := p.TenantID

	var enabledPtr *bool
	if in.Enabled != nil {
		v := in.GetEnabled()
		enabledPtr = &v
	}

	out, err := h.svc.ListSubscriptions(ctx, notify.ListSubscriptionsRequest{
		TenantID:  tenantID,
		ProjectID: in.GetProjectId(),
		Channel:   in.GetChannel(),
		Keyword:   in.GetKeyword(),
		Enabled:   enabledPtr,
		Page:      int(in.GetPage()),
		PageSize:  int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*notifyv1.Subscription, 0, len(out.Subscriptions))
	for _, s := range out.Subscriptions {
		pb = append(pb, subToProto(s))
	}
	//nolint:gosec // out.Total / page / pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&notifyv1.ListSubscriptionsResponse{
		Subscriptions: pb,
		Total:         int32(out.Total),
		Page:          int32(out.Page),
		PageSize:      int32(out.PageSize),
	}), nil
}

func (h *Handler) GetSubscription(
	ctx context.Context,
	req *connect.Request[notifyv1.GetSubscriptionRequest],
) (*connect.Response[notifyv1.GetSubscriptionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	sub, err := h.assertSubVisible(ctx, p, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&notifyv1.GetSubscriptionResponse{Subscription: subToProto(sub)}), nil
}

func (h *Handler) UpdateSubscription(
	ctx context.Context,
	req *connect.Request[notifyv1.UpdateSubscriptionRequest],
) (*connect.Response[notifyv1.UpdateSubscriptionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 更新订阅为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertSubVisible(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}

	in := req.Msg
	cfg := map[string]any{}
	if in.GetConfig() != nil {
		cfg = in.GetConfig().AsMap()
	}
	filter := map[string]any{}
	if in.GetFilter() != nil {
		filter = in.GetFilter().AsMap()
	}
	kinds := make([]notifydomain.EventKind, 0, len(in.GetEventKinds()))
	for _, k := range in.GetEventKinds() {
		kinds = append(kinds, notifydomain.EventKind(k))
	}

	sub, err := h.svc.UpdateSubscription(ctx, notify.UpdateSubscriptionRequest{
		ID:         in.GetId(),
		Name:       in.GetName(),
		EventKinds: kinds,
		Channel:    notifydomain.Channel(in.GetChannel()),
		Config:     cfg,
		Filter:     filter,
		Enabled:    in.GetEnabled(),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	h.logSubAudit(ctx, p, auditdomain.ActionNotifySubUpdated, sub, sub.ID, map[string]any{
		"name":    sub.Name,
		"channel": string(sub.Channel),
		"enabled": sub.Enabled,
	})
	return connect.NewResponse(&notifyv1.UpdateSubscriptionResponse{Subscription: subToProto(sub)}), nil
}

func (h *Handler) DeleteSubscription(
	ctx context.Context,
	req *connect.Request[notifyv1.DeleteSubscriptionRequest],
) (*connect.Response[notifyv1.DeleteSubscriptionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 删除订阅为写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	sub, err := h.assertSubVisible(ctx, p, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteSubscription(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	h.logSubAudit(ctx, p, auditdomain.ActionNotifySubDeleted, sub, req.Msg.GetId(), map[string]any{
		"name": sub.Name,
	})
	return connect.NewResponse(&notifyv1.DeleteSubscriptionResponse{}), nil
}

func (h *Handler) ListDeliveries(
	ctx context.Context,
	req *connect.Request[notifyv1.ListDeliveriesRequest],
) (*connect.Response[notifyv1.ListDeliveriesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg
	if err := h.assertProjectMember(ctx, p, in.GetProjectId()); err != nil {
		return nil, toConnectError(err)
	}

	out, err := h.svc.ListDeliveries(ctx, notify.ListDeliveriesRequest{
		TenantID:       p.TenantID,
		ProjectID:      in.GetProjectId(),
		SubscriptionID: in.GetSubscriptionId(),
		Status:         in.GetStatus(),
		EventKind:      in.GetEventKind(),
		Page:           int(in.GetPage()),
		PageSize:       int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*notifyv1.Delivery, 0, len(out.Deliveries))
	for _, d := range out.Deliveries {
		pb = append(pb, delToProto(d))
	}
	//nolint:gosec // total/page/pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&notifyv1.ListDeliveriesResponse{
		Deliveries: pb,
		Total:      int32(out.Total),
		Page:       int32(out.Page),
		PageSize:   int32(out.PageSize),
	}), nil
}

func (h *Handler) TestSubscription(
	ctx context.Context,
	req *connect.Request[notifyv1.TestSubscriptionRequest],
) (*connect.Response[notifyv1.TestSubscriptionResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// PR-S40: 发测试通知会触发外部 HTTP/邮件出站，等价于写操作，Auditor 拒
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	sub, err := h.assertSubVisible(ctx, p, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.TestSubscription(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	h.logSubAudit(ctx, p, auditdomain.ActionNotifySubTested, sub, req.Msg.GetId(), map[string]any{
		"channel": string(sub.Channel),
	})
	return connect.NewResponse(&notifyv1.TestSubscriptionResponse{}), nil
}

// === BOLA 校验 ===

// assertSubVisible 取订阅并校 caller 是否有权访问。
//   - SA / PlatformAuditor：不限
//   - TA：sub.TenantID == p.TenantID
//   - PA：上 + (sub.ProjectID nil 跨项目 OR ProjectID ∈ memberDB.ListProjectIDsByUser)
func (h *Handler) assertSubVisible(
	ctx context.Context,
	p *auth.UserPrincipal,
	id string,
) (*notifydomain.Subscription, error) {
	sub, err := h.svc.GetSubscription(ctx, id)
	if err != nil {
		return nil, err
	}
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return sub, nil
	case identitydomain.RoleTenantAuditor:
		if sub.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", id)
		}
		return sub, nil
	case identitydomain.RoleProjectAdmin:
		if sub.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", id)
		}
		if sub.ProjectID == nil || *sub.ProjectID == "" {
			return sub, nil // 跨项目订阅对租户内 PA 可见（仅查看 / 不允许改？为简起见允许操作）
		}
		if h.memberDB == nil {
			return nil, errx.New(errx.ErrInternal, "PA 校验需 memberDB 注入")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		for _, pid := range ids {
			if pid == *sub.ProjectID {
				return sub, nil
			}
		}
		return nil, errx.New(errx.ErrChannelNotFound, "subscription 不存在").WithFields("id", id)
	}
	return nil, errx.New(errx.ErrChannelNotFound, "subscription 不存在")
}

// assertProjectMember 创建/列订阅时校 caller 对 project 有访问权。
// projectID 空 = 跨项目订阅，仅 SA / TA 允许创建（PA 必须指定自己加入的项目）。
func (h *Handler) assertProjectMember(
	ctx context.Context,
	p *auth.UserPrincipal,
	projectID string,
) error {
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor, identitydomain.RoleTenantAuditor:
		return nil
	case identitydomain.RoleProjectAdmin:
		if projectID == "" {
			return errx.New(errx.ErrAuthzNotProjectMember, "PA 不能创建跨项目订阅；请指定 project_id")
		}
		if h.memberDB == nil {
			return errx.New(errx.ErrInternal, "PA 校验需 memberDB 注入")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return err
		}
		for _, pid := range ids {
			if pid == projectID {
				return nil
			}
		}
		return errx.New(errx.ErrAuthzNotProjectMember, "未加入该 project").WithFields("project_id", projectID)
	}
	return errx.New(errx.ErrAuthzForbidden, "无权操作")
}

// === Proto 互转 ===

func subToProto(s *notifydomain.Subscription) *notifyv1.Subscription {
	if s == nil {
		return nil
	}
	out := &notifyv1.Subscription{
		Id:        s.ID,
		TenantId:  s.TenantID,
		Name:      s.Name,
		Channel:   string(s.Channel),
		Enabled:   s.Enabled,
		CreatedBy: s.CreatedBy,
		CreatedAt: timestamppb.New(s.CreatedAt),
		UpdatedAt: timestamppb.New(s.UpdatedAt),
	}
	if s.ProjectID != nil {
		out.ProjectId = *s.ProjectID
	}
	out.EventKinds = make([]string, 0, len(s.EventKinds))
	for _, k := range s.EventKinds {
		out.EventKinds = append(out.EventKinds, string(k))
	}
	if pb, err := structpb.NewStruct(s.Config); err == nil {
		out.Config = pb
	}
	if pb, err := structpb.NewStruct(s.Filter); err == nil {
		out.Filter = pb
	}
	return out
}

func delToProto(d *notifydomain.Delivery) *notifyv1.Delivery {
	if d == nil {
		return nil
	}
	//nolint:gosec // attempts ≤ MaxAttempts = 5；溢出 int32 不可能
	out := &notifyv1.Delivery{
		Id:             d.ID,
		SubscriptionId: d.SubscriptionID,
		TenantId:       d.TenantID,
		EventKind:      string(d.EventKind),
		EventTopic:     d.EventTopic,
		Status:         string(d.Status),
		Attempts:       int32(d.Attempts),
		LastError:      d.LastError,
		ScheduledAt:    timestamppb.New(d.ScheduledAt),
		CreatedAt:      timestamppb.New(d.CreatedAt),
	}
	if d.ProjectID != nil {
		out.ProjectId = *d.ProjectID
	}
	if d.SentAt != nil {
		out.SentAt = timestamppb.New(*d.SentAt)
	}
	if pb, err := structpb.NewStruct(d.Payload); err == nil {
		out.Payload = pb
	}
	return out
}

// toConnectError —— 与其它 handler 一致：DomainError → connect.Code。
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
