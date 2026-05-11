// Package handler 是 scan 模块的 ConnectRPC 适配层（PR-S1）。
//
// 复用 identity/handler.RequireAuth + RequireRole；scan 任务需要 SA / TA / PA
// 角色（PA 仅能操作自己加入的项目；MVP 暂不在 service 层强制 PA 限制——
// 后续 PR 加 ProjectMember 校验）。
package handler

import (
	"context"
	"errors"
	"strings"

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
	svc      scan.Service
	authSvc  auth.Service
	memberDB MembershipLookup // PR-S7：PA SearchResults 权限收紧用
}

// MembershipLookup PA 路径专用：查用户加入的项目 ID 列表。
// 与 tenancyrepo.ProjectMemberRepository 的 ListProjectIDsByUser 同签名。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

var _ scanv1connect.ScanServiceHandler = (*Handler)(nil)

// allRoles 接受任何已认证角色（SA / TA / PA / 平台审计）。
var allRoles = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleTenantAuditor,
	identitydomain.RoleProjectAdmin,
	identitydomain.RolePlatformAuditor,
}

// New 构造 ScanService handler。memberDB PA 路径必须传（assertTaskAccess /
// SearchResults / ListAssets 等都要查 join 项目）；SA-only 部署可传 nil。
func New(svc scan.Service, authSvc auth.Service, memberDB MembershipLookup) (*Handler, error) {
	if svc == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "scan.handler.New: 依赖不能为 nil")
	}
	return &Handler{svc: svc, authSvc: authSvc, memberDB: memberDB}, nil
}

// assertTaskAccess（PR-S17 BOLA 收紧）—— 取 task 并校 caller 是否有权访问。
//
// 规则：
//   - SA / PlatformAuditor: 不限
//   - TA: task.TenantID == p.TenantID
//   - PA: 上 + task.ProjectID ∈ memberDB.ListProjectIDsByUser(p.UserID)
//
// 不通过统一返 ErrTaskNotFound（不泄露存在性 / 跨租户枚举攻击）。
func (h *Handler) assertTaskAccess(
	ctx context.Context,
	p *auth.UserPrincipal,
	taskID string,
) (*scandomain.ScanTask, error) {
	t, err := h.svc.GetTask(ctx, taskID)
	if err != nil {
		return nil, err
	}
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return t, nil
	case identitydomain.RoleTenantAuditor:
		if t.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrTaskNotFound, "task 不存在").
				WithFields("id", taskID)
		}
		return t, nil
	case identitydomain.RoleProjectAdmin:
		if t.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrTaskNotFound, "task 不存在").
				WithFields("id", taskID)
		}
		if h.memberDB == nil {
			return nil, errx.New(errx.ErrInternal,
				"PA 校验需 memberDB 注入；handler wire 缺失")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		for _, pid := range ids {
			if pid == t.ProjectID {
				return t, nil
			}
		}
		return nil, errx.New(errx.ErrTaskNotFound, "task 不存在").
			WithFields("id", taskID)
	}
	return nil, errx.New(errx.ErrTaskNotFound, "task 不存在")
}

// assertArtifactKeyAccess（PR-S17）—— artifact key 走 tenant 前缀校验。
//
// key 形态：<tenantID>/<uuid>[.<ext>]（artifact.MakeKey 落地）。
// SA/PlatformAuditor 跨租户不限；TA/PA 必须 key 以本租户 ID + "/" 起头。
// 不通过返 ErrInvalidInput 形态错误（与不存在等价，不泄露存在性）。
func assertArtifactKeyAccess(p *auth.UserPrincipal, key string) error {
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return nil
	}
	if p.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "无权访问该 artifact")
	}
	prefix := p.TenantID + "/"
	if !strings.HasPrefix(key, prefix) {
		return errx.New(errx.ErrInvalidInput, "无权访问该 artifact").
			WithFields("key_prefix", "<masked>")
	}
	return nil
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
	t, err := h.assertTaskAccess(ctx, p, req.Msg.GetId())
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
	if _, err := h.assertTaskAccess(ctx, p, req.Msg.GetId()); err != nil {
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
	if _, err := h.assertTaskAccess(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteTask(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.DeleteScanTaskResponse{}), nil
}

// GetArtifactDownloadURL（PR-S16）—— 给前端拿大文件 result 的预签名下载 URL。
// 同 ListResultsByTask 角色（SA / TA / PA）；service 层签 URL。
func (h *Handler) GetArtifactDownloadURL(
	ctx context.Context,
	req *connect.Request[scanv1.GetArtifactDownloadURLRequest],
) (*connect.Response[scanv1.GetArtifactDownloadURLResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	// PR-S17: tenant 前缀校（SA / PlatformAuditor 跨租户不限）
	if err := assertArtifactKeyAccess(p, req.Msg.GetKey()); err != nil {
		return nil, toConnectError(err)
	}
	url, expires, err := h.svc.GetArtifactDownloadURL(ctx, req.Msg.GetKey())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.GetArtifactDownloadURLResponse{
		Url:       url,
		ExpiresAt: timestamppb.New(expires),
	}), nil
}

// RetryScanTask（PR-S14）—— failed/canceled task 重派。
// 同 CreateScanTask 角色（SA / TA / PA）；service 层校 status。
func (h *Handler) RetryScanTask(
	ctx context.Context,
	req *connect.Request[scanv1.RetryScanTaskRequest],
) (*connect.Response[scanv1.RetryScanTaskResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertTaskAccess(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	t, err := h.svc.RetryTask(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.RetryScanTaskResponse{Task: taskToProto(t)}), nil
}

func (h *Handler) ListTaskAssignments(
	ctx context.Context,
	req *connect.Request[scanv1.ListTaskAssignmentsRequest],
) (*connect.Response[scanv1.ListTaskAssignmentsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertTaskAccess(ctx, p, req.Msg.GetTaskId()); err != nil {
		return nil, toConnectError(err)
	}
	out, err := h.svc.ListAssignmentsByTask(ctx, req.Msg.GetTaskId())
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*scanv1.TaskAssignment, 0, len(out))
	for _, a := range out {
		pb = append(pb, assignmentToProto(a))
	}
	//nolint:gosec // 派发数 ≤ 200 经派发逻辑钳制
	return connect.NewResponse(&scanv1.ListTaskAssignmentsResponse{
		Assignments: pb,
		Total:       int32(len(pb)),
	}), nil
}

func (h *Handler) ListTaskResults(
	ctx context.Context,
	req *connect.Request[scanv1.ListTaskResultsRequest],
) (*connect.Response[scanv1.ListTaskResultsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertTaskAccess(ctx, p, req.Msg.GetTaskId()); err != nil {
		return nil, toConnectError(err)
	}
	out, err := h.svc.ListResultsByTask(ctx, req.Msg.GetTaskId())
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*scanv1.ScanResult, 0, len(out))
	for _, r := range out {
		pb = append(pb, resultToProto(r))
	}
	//nolint:gosec // 行数 ≤ task 累计；MVP < 1000
	return connect.NewResponse(&scanv1.ListTaskResultsResponse{
		Results: pb,
		Total:   int32(len(pb)),
	}), nil
}

// SearchResults 走 ES（PR-S7）—— RBAC：
//   - SA / PlatformAuditor: 不限 tenant / project（subject to req filters）
//   - TA: ScopedTenantID = principal.TenantID
//   - PA: 同上 + ScopedProjectIDs = ListProjectIDsByUser(principal.UserID)
//     0 项目 → service 直接返空页
func (h *Handler) SearchResults(
	ctx context.Context,
	req *connect.Request[scanv1.SearchResultsRequest],
) (*connect.Response[scanv1.SearchResultsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}

	sr := scan.SearchRequest{
		Keyword:   req.Msg.GetKeyword(),
		Kind:      req.Msg.GetKind(),
		ProjectID: req.Msg.GetProjectId(),
		NodeID:    req.Msg.GetNodeId(),
		TaskID:    req.Msg.GetTaskId(),
		Page:      int(req.Msg.GetPage()),
		PageSize:  int(req.Msg.GetPageSize()),
	}
	if t := req.Msg.GetTimeFrom(); t != nil {
		x := t.AsTime()
		sr.TimeFrom = &x
	}
	if t := req.Msg.GetTimeTo(); t != nil {
		x := t.AsTime()
		sr.TimeTo = &x
	}

	// RBAC 注入
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		// 不限
	case identitydomain.RoleTenantAuditor:
		sr.ScopedTenantID = p.TenantID
	case identitydomain.RoleProjectAdmin:
		sr.ScopedTenantID = p.TenantID
		if h.memberDB == nil {
			return nil, toConnectError(errx.New(errx.ErrInternal,
				"scan.SearchResults: PA 模式需 memberDB 注入"))
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, toConnectError(err)
		}
		// 即使空列表也注入空切片，让 service 走"返空页"分支（不 nil）
		if ids == nil {
			ids = []string{}
		}
		sr.ScopedProjectIDs = ids
	}

	page, err := h.svc.SearchResults(ctx, sr)
	if err != nil {
		return nil, toConnectError(err)
	}
	pbResults := make([]*scanv1.ScanResult, 0, len(page.Items))
	for _, r := range page.Items {
		pbResults = append(pbResults, resultToProto(r))
	}
	pbFacets := make([]*scanv1.Facet, 0, len(page.Facets))
	for _, f := range page.Facets {
		buckets := make([]*scanv1.FacetBucket, 0, len(f.Buckets))
		for _, b := range f.Buckets {
			//nolint:gosec // facet 计数 ≤ ES doc count，超 int32 不现实
			buckets = append(buckets, &scanv1.FacetBucket{Key: b.Key, Count: int32(b.Count)})
		}
		pbFacets = append(pbFacets, &scanv1.Facet{Field: f.Field, Buckets: buckets})
	}
	//nolint:gosec // total/page/page_size 同上
	return connect.NewResponse(&scanv1.SearchResultsResponse{
		Results:  pbResults,
		Total:    int32(page.Total),
		Page:     int32(page.Page),
		PageSize: int32(page.PageSize),
		Facets:   pbFacets,
	}), nil
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
	if t.SourceTaskID != nil {
		out.SourceTaskId = *t.SourceTaskID
	}
	return out
}

func assignmentToProto(a *scandomain.TaskAssignment) *scanv1.TaskAssignment {
	if a == nil {
		return nil
	}
	out := &scanv1.TaskAssignment{
		Id:         a.ID,
		TaskId:     a.TaskID,
		NodeId:     a.NodeID,
		Status:     string(a.Status),
		AssignedAt: timestamppb.New(a.AssignedAt),
		Error:      a.Error,
	}
	if a.PulledAt != nil {
		out.PulledAt = timestamppb.New(*a.PulledAt)
	}
	if a.StartedAt != nil {
		out.StartedAt = timestamppb.New(*a.StartedAt)
	}
	if a.FinishedAt != nil {
		out.FinishedAt = timestamppb.New(*a.FinishedAt)
	}
	return out
}

func resultToProto(r *scandomain.ScanResult) *scanv1.ScanResult {
	if r == nil {
		return nil
	}
	out := &scanv1.ScanResult{
		Id:           r.ID,
		TenantId:     r.TenantID,
		ProjectId:    r.ProjectID,
		TaskId:       r.TaskID,
		AssignmentId: r.AssignmentID,
		NodeId:       r.NodeID,
		Kind:         string(r.Kind),
		CreatedAt:    timestamppb.New(r.CreatedAt),
	}
	if s, err := structpb.NewStruct(r.Data); err == nil {
		out.Data = s
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
