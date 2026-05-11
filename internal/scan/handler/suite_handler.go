// PR-S23 扫描套件 ConnectRPC adapter。
package handler

import (
	"context"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	scanv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// CreateScanSuite 4 角色都能调；PA 创建必须传 project_id，且属于自己加入的项目。
func (h *Handler) CreateScanSuite(
	ctx context.Context,
	req *connect.Request[scanv1.CreateScanSuiteRequest],
) (*connect.Response[scanv1.CreateScanSuiteResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg

	// PA 必须传 project_id 且属于自己加入项目；不允许创建跨项目套件
	var projectID *string
	if pid := strings.TrimSpace(in.GetProjectId()); pid != "" {
		projectID = &pid
		if err := h.assertProjectMember(ctx, p, pid); err != nil {
			return nil, toConnectError(err)
		}
	} else if p.Role == identitydomain.RoleProjectAdmin {
		// 空 = 跨项目套件；仅 SA / TA 可以
		return nil, toConnectError(errx.New(errx.ErrAuthzNotProjectMember,
			"PA 不能创建跨项目套件，请指定 project_id"))
	}

	kinds := make([]scandomain.TaskKind, 0, len(in.GetKinds()))
	for _, k := range in.GetKinds() {
		kinds = append(kinds, scandomain.TaskKind(k))
	}
	defaults := map[string]any{}
	if in.DefaultSettings != nil {
		defaults = in.DefaultSettings.AsMap()
	}
	suite, err := h.svc.CreateSuite(ctx, scan.CreateSuiteRequest{
		TenantID:        p.TenantID,
		ProjectID:       projectID,
		Name:            in.GetName(),
		Kinds:           kinds,
		TargetKind:      scandomain.TargetKind(in.GetTargetKind()),
		DefaultSettings: defaults,
		CreatedBy:       p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.CreateScanSuiteResponse{Suite: suiteToProto(suite)}), nil
}

// ListScanSuites 4 角色都能调；TA 限本租户，PA 仅返其加入项目 + 跨项目套件。
func (h *Handler) ListScanSuites(
	ctx context.Context,
	req *connect.Request[scanv1.ListScanSuitesRequest],
) (*connect.Response[scanv1.ListScanSuitesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg
	tenantID := p.TenantID
	if p.Role == identitydomain.RoleSuperAdmin || p.Role == identitydomain.RolePlatformAuditor {
		// SA / Audit 跨租户：tenantID 空让 service 不加过滤
		tenantID = ""
	}
	out, err := h.svc.ListSuites(ctx, scan.ListSuitesRequest{
		TenantID:  tenantID,
		ProjectID: in.GetProjectId(),
		Keyword:   in.GetKeyword(),
		Page:      int(in.GetPage()),
		PageSize:  int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*scanv1.ScanSuite, 0, len(out.Suites))
	for _, s := range out.Suites {
		pb = append(pb, suiteToProto(s))
	}
	//nolint:gosec // 计数 ≤ 200
	return connect.NewResponse(&scanv1.ListScanSuitesResponse{
		Suites: pb, Total: int32(out.Total), Page: int32(out.Page), PageSize: int32(out.PageSize),
	}), nil
}

// GetScanSuite 复用 ListScanSuites 同样的可见性约束（BOLA 收紧）。
func (h *Handler) GetScanSuite(
	ctx context.Context,
	req *connect.Request[scanv1.GetScanSuiteRequest],
) (*connect.Response[scanv1.GetScanSuiteResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	suite, err := h.assertSuiteAccess(ctx, p, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.GetScanSuiteResponse{Suite: suiteToProto(suite)}), nil
}

// DeleteScanSuite SA/TA/PA（限本租户/项目）。
func (h *Handler) DeleteScanSuite(
	ctx context.Context,
	req *connect.Request[scanv1.DeleteScanSuiteRequest],
) (*connect.Response[scanv1.DeleteScanSuiteResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p,
		identitydomain.RoleSuperAdmin,
		identitydomain.RoleTenantAuditor,
		identitydomain.RoleProjectAdmin); err != nil {
		return nil, toConnectError(err)
	}
	if _, err := h.assertSuiteAccess(ctx, p, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.DeleteSuite(ctx, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.DeleteScanSuiteResponse{}), nil
}

// RunScanSuite 4 角色都能调；PA 必须属于 project_id 项目。
func (h *Handler) RunScanSuite(
	ctx context.Context,
	req *connect.Request[scanv1.RunScanSuiteRequest],
) (*connect.Response[scanv1.RunScanSuiteResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg
	if _, err := h.assertSuiteAccess(ctx, p, in.GetSuiteId()); err != nil {
		return nil, toConnectError(err)
	}
	if err := h.assertProjectMember(ctx, p, in.GetProjectId()); err != nil {
		return nil, toConnectError(err)
	}
	run, err := h.svc.RunSuite(ctx, scan.RunSuiteRequest{
		SuiteID:   in.GetSuiteId(),
		ProjectID: in.GetProjectId(),
		Targets:   in.GetTargets(),
		CreatedBy: p.UserID,
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&scanv1.RunScanSuiteResponse{Run: suiteRunToProto(run)}), nil
}

// GetScanSuiteRun 4 角色；PA 限 run.project 属本人加入项目。
func (h *Handler) GetScanSuiteRun(
	ctx context.Context,
	req *connect.Request[scanv1.GetScanSuiteRunRequest],
) (*connect.Response[scanv1.GetScanSuiteRunResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	detail, err := h.svc.GetSuiteRun(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.assertSuiteRunVisible(ctx, p, detail.Run); err != nil {
		return nil, toConnectError(err)
	}
	pb := &scanv1.GetScanSuiteRunResponse{
		Run:   suiteRunToProto(detail.Run),
		Tasks: make([]*scanv1.ScanTask, 0, len(detail.Tasks)),
	}
	if detail.Suite != nil {
		pb.Suite = suiteToProto(detail.Suite)
	}
	for _, t := range detail.Tasks {
		pb.Tasks = append(pb.Tasks, taskToProto(t))
	}
	return connect.NewResponse(pb), nil
}

// ListScanSuiteRuns 4 角色；TA 限本租户 + PA 仅看 join 项目的 run。
func (h *Handler) ListScanSuiteRuns(
	ctx context.Context,
	req *connect.Request[scanv1.ListScanSuiteRunsRequest],
) (*connect.Response[scanv1.ListScanSuiteRunsResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, allRoles...); err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg
	tenantID := p.TenantID
	if p.Role == identitydomain.RoleSuperAdmin || p.Role == identitydomain.RolePlatformAuditor {
		tenantID = ""
	}
	// PA：要么传具体 project_id 校 member，要么强制只看自己加入项目
	projectID := strings.TrimSpace(in.GetProjectId())
	if p.Role == identitydomain.RoleProjectAdmin {
		if projectID == "" {
			return nil, toConnectError(errx.New(errx.ErrInvalidInput,
				"PA ListSuiteRuns 必须指定 project_id"))
		}
		if err := h.assertProjectMember(ctx, p, projectID); err != nil {
			return nil, toConnectError(err)
		}
	}
	out, err := h.svc.ListSuiteRuns(ctx, scan.ListSuiteRunsRequest{
		TenantID:  tenantID,
		ProjectID: projectID,
		SuiteID:   in.GetSuiteId(),
		Page:      int(in.GetPage()),
		PageSize:  int(in.GetPageSize()),
	})
	if err != nil {
		return nil, toConnectError(err)
	}
	pb := make([]*scanv1.ScanSuiteRun, 0, len(out.Runs))
	for _, r := range out.Runs {
		pb = append(pb, suiteRunToProto(r))
	}
	//nolint:gosec // total/page/pageSize ≤ 200 经分页钳制；溢出 int32 不可能
	return connect.NewResponse(&scanv1.ListScanSuiteRunsResponse{
		Runs: pb, Total: int32(out.Total), Page: int32(out.Page), PageSize: int32(out.PageSize),
	}), nil
}

// === BOLA helpers ===

// assertSuiteAccess 校 caller 是否能看到该 suite。
//
// 规则：
//   - SA / PlatformAuditor: 不限
//   - TA: suite.TenantID == p.TenantID
//   - PA: 上 + (suite.ProjectID nil 跨项目套件 同租户即可 OR project ∈ joined)
func (h *Handler) assertSuiteAccess(
	ctx context.Context,
	p *auth.UserPrincipal,
	suiteID string,
) (*scandomain.ScanSuite, error) {
	suite, err := h.svc.GetSuite(ctx, suiteID)
	if err != nil {
		return nil, err
	}
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return suite, nil
	case identitydomain.RoleTenantAuditor:
		if suite.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrTaskNotFound, "suite 不存在").WithFields("id", suiteID)
		}
		return suite, nil
	case identitydomain.RoleProjectAdmin:
		if suite.TenantID != p.TenantID {
			return nil, errx.New(errx.ErrTaskNotFound, "suite 不存在").WithFields("id", suiteID)
		}
		if suite.ProjectID == nil {
			return suite, nil // 跨项目套件同租户 PA 可见
		}
		if h.memberDB == nil {
			return nil, errx.New(errx.ErrInternal, "PA 校验需 memberDB 注入")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		for _, pid := range ids {
			if pid == *suite.ProjectID {
				return suite, nil
			}
		}
		return nil, errx.New(errx.ErrTaskNotFound, "suite 不存在").WithFields("id", suiteID)
	}
	return nil, errx.New(errx.ErrTaskNotFound, "suite 不存在")
}

// assertSuiteRunVisible 校 run 可见。run 必落具体项目，规则与 task 一致。
func (h *Handler) assertSuiteRunVisible(
	ctx context.Context,
	p *auth.UserPrincipal,
	run *scandomain.ScanSuiteRun,
) error {
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		return nil
	case identitydomain.RoleTenantAuditor:
		if run.TenantID != p.TenantID {
			return errx.New(errx.ErrTaskNotFound, "suite_run 不存在").WithFields("id", run.ID)
		}
		return nil
	case identitydomain.RoleProjectAdmin:
		if run.TenantID != p.TenantID {
			return errx.New(errx.ErrTaskNotFound, "suite_run 不存在").WithFields("id", run.ID)
		}
		return h.assertProjectMember(ctx, p, run.ProjectID)
	}
	return errx.New(errx.ErrTaskNotFound, "suite_run 不存在")
}

// assertProjectMember PA 校 project 加入；SA/TA/Audit 直接通过。
func (h *Handler) assertProjectMember(
	ctx context.Context,
	p *auth.UserPrincipal,
	projectID string,
) error {
	if p.Role != identitydomain.RoleProjectAdmin {
		return nil
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
	return errx.New(errx.ErrAuthzNotProjectMember, "PA 不属于该项目")
}

// === conv ===

func suiteToProto(s *scandomain.ScanSuite) *scanv1.ScanSuite {
	if s == nil {
		return nil
	}
	out := &scanv1.ScanSuite{
		Id:         s.ID,
		TenantId:   s.TenantID,
		Name:       s.Name,
		TargetKind: string(s.TargetKind),
		CreatedBy:  s.CreatedBy,
		CreatedAt:  timestamppb.New(s.CreatedAt),
		UpdatedAt:  timestamppb.New(s.UpdatedAt),
	}
	if s.ProjectID != nil {
		out.ProjectId = *s.ProjectID
	}
	out.Kinds = make([]string, 0, len(s.Kinds))
	for _, k := range s.Kinds {
		out.Kinds = append(out.Kinds, string(k))
	}
	if ds, err := structpb.NewStruct(s.DefaultSettings); err == nil {
		out.DefaultSettings = ds
	}
	return out
}

func suiteRunToProto(r *scandomain.ScanSuiteRun) *scanv1.ScanSuiteRun {
	if r == nil {
		return nil
	}
	out := &scanv1.ScanSuiteRun{
		Id:        r.ID,
		SuiteId:   r.SuiteID,
		TenantId:  r.TenantID,
		ProjectId: r.ProjectID,
		Targets:   append([]string(nil), r.Targets...),
		Status:    string(r.Status),
		CreatedBy: r.CreatedBy,
		CreatedAt: timestamppb.New(r.CreatedAt),
		UpdatedAt: timestamppb.New(r.UpdatedAt),
	}
	if r.FinishedAt != nil {
		out.FinishedAt = timestamppb.New(*r.FinishedAt)
	}
	return out
}
