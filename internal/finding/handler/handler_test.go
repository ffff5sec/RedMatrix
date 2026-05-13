// finding/handler/handler_test.go PR-S46-C —— finding handler RBAC + BOLA test.
//
// 矩阵：
//   - 读路径（ListFindings/GetFinding/ListEvents）— 全 4 角色 OK
//   - 写路径（Transition/Comment/Assign）— SA / PA OK；TA / PA-Audit 拒
//   - BOLA assertFindingVisible：TA 跨租户访问返 FindingNotFound（防枚举）；
//     PA wire 缺失 memberDB 返 Internal；PA 项目命中放行
package handler

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	findingv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/finding/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/finding"
	findingdomain "github.com/ffff5sec/RedMatrix/internal/finding/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// === stubs ===

type stubFindingSvc struct {
	listRes    *finding.ListFindingsResult
	getRes     *findingdomain.Finding
	getErr     error
	transRes   *findingdomain.Finding
	transErr   error
	commentRes *findingdomain.FindingEvent
	commentErr error
	assignRes  *findingdomain.Finding
	assignErr  error
	eventsRes  []*findingdomain.FindingEvent
}

func (s *stubFindingSvc) ListFindings(_ context.Context, _ finding.ListFindingsRequest) (*finding.ListFindingsResult, error) {
	return s.listRes, nil
}
func (s *stubFindingSvc) GetFinding(_ context.Context, _ string) (*findingdomain.Finding, error) {
	return s.getRes, s.getErr
}
func (s *stubFindingSvc) ListEvents(_ context.Context, _ string) ([]*findingdomain.FindingEvent, error) {
	return s.eventsRes, nil
}
func (s *stubFindingSvc) Transition(_ context.Context, _ finding.TransitionRequest) (*findingdomain.Finding, error) {
	return s.transRes, s.transErr
}
func (s *stubFindingSvc) Comment(_ context.Context, _ finding.CommentRequest) (*findingdomain.FindingEvent, error) {
	return s.commentRes, s.commentErr
}
func (s *stubFindingSvc) Assign(_ context.Context, _ finding.AssignRequest) (*findingdomain.Finding, error) {
	return s.assignRes, s.assignErr
}
func (s *stubFindingSvc) UpsertFromResult(_ context.Context, _ finding.UpsertFromResultRequest) (*findingdomain.Finding, bool, error) {
	panic("unexpected: UpsertFromResult")
}

var _ finding.Service = (*stubFindingSvc)(nil)

type stubAuthSvc struct {
	princ *auth.UserPrincipal
	err   error
}

func (s *stubAuthSvc) AuthenticateBearer(_ context.Context, _ string) (*auth.UserPrincipal, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.princ, nil
}
func (s *stubAuthSvc) Login(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
	panic("unexpected: Login")
}
func (s *stubAuthSvc) Logout(_ context.Context, _ string) error { panic("unexpected: Logout") }
func (s *stubAuthSvc) LogoutAllSessions(_ context.Context, _ string) error {
	panic("unexpected: LogoutAllSessions")
}
func (s *stubAuthSvc) CreateAPIKey(_ context.Context, _ auth.CreateAPIKeyRequest) (*auth.CreateAPIKeyResult, error) {
	panic("unexpected: CreateAPIKey")
}
func (s *stubAuthSvc) ListAPIKeys(_ context.Context, _ string) ([]*identitydomain.APIKey, error) {
	panic("unexpected: ListAPIKeys")
}
func (s *stubAuthSvc) RevokeAPIKey(_ context.Context, _, _ string) error {
	panic("unexpected: RevokeAPIKey")
}
func (s *stubAuthSvc) GetCurrentUser(_ context.Context, _ string) (*identitydomain.User, error) {
	panic("unexpected: GetCurrentUser")
}
func (s *stubAuthSvc) ChangePassword(_ context.Context, _, _, _ string) error {
	panic("unexpected: ChangePassword")
}
func (s *stubAuthSvc) CreateUser(_ context.Context, _ auth.CreateUserRequest) (*auth.CreateUserResult, error) {
	panic("unexpected: CreateUser")
}
func (s *stubAuthSvc) ListUsers(_ context.Context, _ auth.ListUsersRequest) (*auth.ListUsersResult, error) {
	panic("unexpected: ListUsers")
}
func (s *stubAuthSvc) GetUser(_ context.Context, _ string) (*identitydomain.User, error) {
	panic("unexpected: GetUser")
}
func (s *stubAuthSvc) EnableUser(_ context.Context, _ string) error {
	panic("unexpected: EnableUser")
}
func (s *stubAuthSvc) DisableUser(_ context.Context, _ string) error {
	panic("unexpected: DisableUser")
}
func (s *stubAuthSvc) ResetPassword(_ context.Context, _ string) (string, error) {
	panic("unexpected: ResetPassword")
}
func (s *stubAuthSvc) ForceLogout(_ context.Context, _ string) error {
	panic("unexpected: ForceLogout")
}

var _ auth.Service = (*stubAuthSvc)(nil)

type stubMemberDB struct {
	ids []string
	err error
}

func (m *stubMemberDB) ListProjectIDsByUser(_ context.Context, _ string) ([]string, error) {
	return m.ids, m.err
}

// === helpers ===

const (
	fixtureFindingID = "find-1"
	fixtureTenantID  = "T1"
	fixtureProjectID = "P1"
)

func principal(role identitydomain.Role, tenantID, userID string) *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID: userID, TenantID: tenantID, Username: "tester",
		Role: role, Source: auth.PrincipalSourceJWT,
	}
}

func authHeaderReq[T any](msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer x")
	return r
}

func requireConnectCode(t *testing.T, err error, wantConnect connect.Code, wantErrx errx.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, wantConnect, connect.CodeOf(err),
		"connect.Code mismatch: got=%v want=%v err=%v", connect.CodeOf(err), wantConnect, err)
	assert.Contains(t, err.Error(), string(wantErrx))
}

func findingFixture() *findingdomain.Finding {
	return &findingdomain.Finding{
		ID:        fixtureFindingID,
		TenantID:  fixtureTenantID,
		ProjectID: fixtureProjectID,
		Status:    findingdomain.FindingOpen,
		Severity:  findingdomain.SeverityHigh,
	}
}

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubFindingSvc, mem MembershipLookup) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ}, mem)
	require.NoError(t, err)
	return h
}

// === 写路径 RBAC：writers (SA+PA) ===

// writerOp 描述一个写 RPC 的最小调用 helper。
type writerOp struct {
	name string
	call func(t *testing.T, h *Handler) error
}

func writerOps() []writerOp {
	return []writerOp{
		{
			name: "Transition",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.Transition(context.Background(),
					authHeaderReq(&findingv1.TransitionRequest{
						Id: fixtureFindingID, ToStatus: "triaged",
					}))
				return err
			},
		},
		{
			name: "Comment",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.Comment(context.Background(),
					authHeaderReq(&findingv1.CommentRequest{
						FindingId: fixtureFindingID, Body: "hello",
					}))
				return err
			},
		},
		{
			name: "Assign",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.Assign(context.Background(),
					authHeaderReq(&findingv1.AssignRequest{
						Id: fixtureFindingID, AssigneeId: "u-2",
					}))
				return err
			},
		},
	}
}

// TestWriterOps_AuditorRoles_Rejected：HLD §4.3 Auditor 只读。
func TestWriterOps_AuditorRoles_Rejected(t *testing.T) {
	for _, op := range writerOps() {
		t.Run(op.name+"/TA", func(t *testing.T) {
			h := newHandler(t,
				principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"),
				&stubFindingSvc{}, nil)
			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
		})
		t.Run(op.name+"/PlatformAuditor", func(t *testing.T) {
			h := newHandler(t,
				principal(identitydomain.RolePlatformAuditor, "", "pa-aud-1"),
				&stubFindingSvc{}, nil)
			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
		})
	}
}

// TestWriterOps_SA_PA_OK：SA / PA 写路径放行（service 返成功）。
func TestWriterOps_SA_PA_OK(t *testing.T) {
	for _, op := range writerOps() {
		t.Run(op.name+"/SA", func(t *testing.T) {
			svc := &stubFindingSvc{
				getRes: findingFixture(), transRes: findingFixture(),
				commentRes: &findingdomain.FindingEvent{ID: "ev-1"},
				assignRes:  findingFixture(),
			}
			h := newHandler(t, principal(identitydomain.RoleSuperAdmin, "", "sa-1"), svc, nil)
			err := op.call(t, h)
			require.NoError(t, err)
		})
		t.Run(op.name+"/PA", func(t *testing.T) {
			svc := &stubFindingSvc{
				getRes: findingFixture(), transRes: findingFixture(),
				commentRes: &findingdomain.FindingEvent{ID: "ev-1"},
				assignRes:  findingFixture(),
			}
			mem := &stubMemberDB{ids: []string{fixtureProjectID}}
			h := newHandler(t,
				principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
			err := op.call(t, h)
			require.NoError(t, err)
		})
	}
}

// === BOLA assertFindingVisible ===

// TestGetFinding_TACrossTenant_ReturnsNotFound: TA 调 Get 跨租户的 finding，
// 返 FindingNotFound（防枚举）。
func TestGetFinding_TACrossTenant_ReturnsNotFound(t *testing.T) {
	f := findingFixture()
	f.TenantID = "T-OTHER"
	h := newHandler(t,
		principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"),
		&stubFindingSvc{getRes: f}, nil)
	_, err := h.GetFinding(context.Background(),
		authHeaderReq(&findingv1.GetFindingRequest{Id: fixtureFindingID}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrFindingNotFound)
}

// TestGetFinding_PAProjectMatch_OK: PA 命中项目可见。
func TestGetFinding_PAProjectMatch_OK(t *testing.T) {
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"),
		&stubFindingSvc{getRes: findingFixture()},
		&stubMemberDB{ids: []string{fixtureProjectID}})
	_, err := h.GetFinding(context.Background(),
		authHeaderReq(&findingv1.GetFindingRequest{Id: fixtureFindingID}))
	require.NoError(t, err)
}

// TestGetFinding_PAProjectMiss_ReturnsNotFound: PA 不在项目成员里 → NotFound。
func TestGetFinding_PAProjectMiss_ReturnsNotFound(t *testing.T) {
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"),
		&stubFindingSvc{getRes: findingFixture()},
		&stubMemberDB{ids: []string{"P-OTHER"}})
	_, err := h.GetFinding(context.Background(),
		authHeaderReq(&findingv1.GetFindingRequest{Id: fixtureFindingID}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrFindingNotFound)
}

// TestGetFinding_PA_NilMemberDB_Internal: PA wire 缺 memberDB → Internal。
func TestGetFinding_PA_NilMemberDB_Internal(t *testing.T) {
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"),
		&stubFindingSvc{getRes: findingFixture()}, nil)
	_, err := h.GetFinding(context.Background(),
		authHeaderReq(&findingv1.GetFindingRequest{Id: fixtureFindingID}))
	requireConnectCode(t, err, connect.CodeInternal, errx.ErrInternal)
}

// === 读路径 RBAC ===

// TestListFindings_AllRoles_OK：4 角色读路径均可。
func TestListFindings_AllRoles_OK(t *testing.T) {
	roles := []identitydomain.Role{
		identitydomain.RoleSuperAdmin,
		identitydomain.RoleTenantAuditor,
		identitydomain.RolePlatformAuditor,
		identitydomain.RoleProjectAdmin,
	}
	for _, r := range roles {
		t.Run(string(r), func(t *testing.T) {
			svc := &stubFindingSvc{
				listRes: &finding.ListFindingsResult{Page: 1, PageSize: 50},
			}
			var mem MembershipLookup
			if r == identitydomain.RoleProjectAdmin {
				mem = &stubMemberDB{ids: []string{fixtureProjectID}}
			}
			h := newHandler(t, principal(r, fixtureTenantID, "u-1"), svc, mem)
			_, err := h.ListFindings(context.Background(),
				authHeaderReq(&findingv1.ListFindingsRequest{}))
			require.NoError(t, err)
		})
	}
}
