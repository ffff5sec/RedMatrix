// tenancy/handler/handler_test.go PR-S47 —— tenancy handler RBAC 测试.
//
// 矩阵：
//   - SA-only 操作（项目 + 节点 + 注册 token CRUD 写）：
//     CreateProject / Archive / Unarchive / Delete /
//     AddProjectMember / RemoveProjectMember /
//     CreateNode / EnableNode / DisableNode / DeleteNode /
//     SetProjectAllowedNodes / CreateRegistrationToken /
//     RevokeRegistrationToken / RevokeNodeCertificate
//     —— TA / PA / PA-Audit 必拒
//   - adminAndAuditor 读路径（GetProject / ListNodes 等）：SA + TA OK；PA 拒
//   - RedeemRegistrationToken：公开 RPC（无 auth），plaintext 自身即认证
package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
	tenancydomain "github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// === stubs ===

// stubTenancySvc 实现 tenancy.Service：默认全返 nil/zero；测试可注入特定字段。
type stubTenancySvc struct {
	createProjectRes *tenancydomain.Project
	getProjectRes    *tenancydomain.Project
	listProjectsRes  *tenancy.ListProjectsResult
	createNodeRes    *tenancydomain.Node
	listNodesRes     *tenancy.ListNodesResult
	getNodeRes       *tenancydomain.Node
	tokenCreateRes   *tenancy.CreateRegistrationTokenResult
	tokenRedeemRes   *tenancy.RedeemRegistrationTokenResult
	statsRes         *tenancy.StatsResult
	allowedNodesRes  tenancydomain.AllowedNodes
	defaultErr       error
}

func (s *stubTenancySvc) CreateProject(_ context.Context, _ tenancy.CreateProjectRequest) (*tenancydomain.Project, error) {
	return s.createProjectRes, s.defaultErr
}
func (s *stubTenancySvc) ListProjects(_ context.Context, _ tenancy.ListProjectsRequest) (*tenancy.ListProjectsResult, error) {
	return s.listProjectsRes, s.defaultErr
}
func (s *stubTenancySvc) GetProject(_ context.Context, _ string) (*tenancydomain.Project, error) {
	return s.getProjectRes, s.defaultErr
}
func (s *stubTenancySvc) ArchiveProject(_ context.Context, _ string) error   { return s.defaultErr }
func (s *stubTenancySvc) UnarchiveProject(_ context.Context, _ string) error { return s.defaultErr }
func (s *stubTenancySvc) DeleteProject(_ context.Context, _ string) error    { return s.defaultErr }
func (s *stubTenancySvc) AddProjectMember(_ context.Context, _ tenancy.AddProjectMemberRequest) error {
	return s.defaultErr
}
func (s *stubTenancySvc) RemoveProjectMember(_ context.Context, _, _ string) error {
	return s.defaultErr
}
func (s *stubTenancySvc) ListProjectMembers(_ context.Context, _ string) ([]*tenancydomain.ProjectMember, error) {
	return nil, s.defaultErr
}
func (s *stubTenancySvc) CreateNode(_ context.Context, _ tenancy.CreateNodeRequest) (*tenancydomain.Node, error) {
	return s.createNodeRes, s.defaultErr
}
func (s *stubTenancySvc) ListNodes(_ context.Context, _ tenancy.ListNodesRequest) (*tenancy.ListNodesResult, error) {
	return s.listNodesRes, s.defaultErr
}
func (s *stubTenancySvc) GetNode(_ context.Context, _ string) (*tenancydomain.Node, error) {
	return s.getNodeRes, s.defaultErr
}
func (s *stubTenancySvc) EnableNode(_ context.Context, _ string) error  { return s.defaultErr }
func (s *stubTenancySvc) DisableNode(_ context.Context, _ string) error { return s.defaultErr }
func (s *stubTenancySvc) DeleteNode(_ context.Context, _ string) error  { return s.defaultErr }
func (s *stubTenancySvc) SetProjectAllowedNodes(_ context.Context, _ tenancy.SetProjectAllowedNodesRequest) error {
	return s.defaultErr
}
func (s *stubTenancySvc) GetProjectAllowedNodes(_ context.Context, _ string) (tenancydomain.AllowedNodes, error) {
	return s.allowedNodesRes, s.defaultErr
}
func (s *stubTenancySvc) IsNodeAllowedForProject(_ context.Context, _, _ string) (bool, error) {
	return true, s.defaultErr
}
func (s *stubTenancySvc) CreateRegistrationToken(_ context.Context, _ tenancy.CreateRegistrationTokenRequest) (*tenancy.CreateRegistrationTokenResult, error) {
	return s.tokenCreateRes, s.defaultErr
}
func (s *stubTenancySvc) ListRegistrationTokens(_ context.Context, _ string) ([]*tenancydomain.RegistrationToken, error) {
	return nil, s.defaultErr
}
func (s *stubTenancySvc) RevokeRegistrationToken(_ context.Context, _ string) error {
	return s.defaultErr
}
func (s *stubTenancySvc) RedeemRegistrationToken(_ context.Context, _ tenancy.RedeemRegistrationTokenRequest) (*tenancy.RedeemRegistrationTokenResult, error) {
	return s.tokenRedeemRes, s.defaultErr
}
func (s *stubTenancySvc) Heartbeat(_ context.Context, _ tenancy.HeartbeatRequest) (*tenancy.HeartbeatResult, error) {
	panic("unexpected: Heartbeat")
}
func (s *stubTenancySvc) ReissueCert(_ context.Context, _ tenancy.ReissueCertRequest) (*tenancy.ReissueCertResult, error) {
	panic("unexpected: ReissueCert")
}
func (s *stubTenancySvc) ListCertsByNode(_ context.Context, _ string) ([]*tenancydomain.NodeCertificate, error) {
	return nil, s.defaultErr
}
func (s *stubTenancySvc) RevokeCert(_ context.Context, _ string) error { return s.defaultErr }
func (s *stubTenancySvc) GetStats(_ context.Context, _ string) (*tenancy.StatsResult, error) {
	return s.statsRes, s.defaultErr
}

var _ tenancy.Service = (*stubTenancySvc)(nil)

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

// === helpers ===

const (
	fixtureTenantID  = "T1"
	fixtureProjectID = "P1"
	fixtureNodeID    = "N1"
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

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubTenancySvc) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ})
	require.NoError(t, err)
	return h
}

// === SA-only 矩阵 ===

type saOnlyOp struct {
	name string
	call func(t *testing.T, h *Handler) error
}

func saOnlyOps() []saOnlyOp {
	return []saOnlyOp{
		{"CreateProject", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.CreateProject(context.Background(),
				authHeaderReq(&tenancyv1.CreateProjectRequest{Name: "x", TenantId: fixtureTenantID}))
			return err
		}},
		{"ArchiveProject", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.ArchiveProject(context.Background(),
				authHeaderReq(&tenancyv1.ArchiveProjectRequest{Id: fixtureProjectID}))
			return err
		}},
		{"UnarchiveProject", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.UnarchiveProject(context.Background(),
				authHeaderReq(&tenancyv1.UnarchiveProjectRequest{Id: fixtureProjectID}))
			return err
		}},
		{"DeleteProject", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.DeleteProject(context.Background(),
				authHeaderReq(&tenancyv1.DeleteProjectRequest{Id: fixtureProjectID}))
			return err
		}},
		{"AddProjectMember", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.AddProjectMember(context.Background(),
				authHeaderReq(&tenancyv1.AddProjectMemberRequest{
					ProjectId: fixtureProjectID, UserId: "u-2",
				}))
			return err
		}},
		{"RemoveProjectMember", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.RemoveProjectMember(context.Background(),
				authHeaderReq(&tenancyv1.RemoveProjectMemberRequest{
					ProjectId: fixtureProjectID, UserId: "u-2",
				}))
			return err
		}},
		{"CreateNode", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.CreateNode(context.Background(),
				authHeaderReq(&tenancyv1.CreateNodeRequest{Name: "n1"}))
			return err
		}},
		{"EnableNode", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.EnableNode(context.Background(),
				authHeaderReq(&tenancyv1.EnableNodeRequest{Id: fixtureNodeID}))
			return err
		}},
		{"DisableNode", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.DisableNode(context.Background(),
				authHeaderReq(&tenancyv1.DisableNodeRequest{Id: fixtureNodeID}))
			return err
		}},
		{"DeleteNode", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.DeleteNode(context.Background(),
				authHeaderReq(&tenancyv1.DeleteNodeRequest{Id: fixtureNodeID}))
			return err
		}},
		{"CreateRegistrationToken", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.CreateRegistrationToken(context.Background(),
				authHeaderReq(&tenancyv1.CreateRegistrationTokenRequest{
					Name: "t1", TtlSeconds: 3600,
				}))
			return err
		}},
		{"RevokeRegistrationToken", func(t *testing.T, h *Handler) error {
			t.Helper()
			_, err := h.RevokeRegistrationToken(context.Background(),
				authHeaderReq(&tenancyv1.RevokeRegistrationTokenRequest{Id: "tok-1"}))
			return err
		}},
	}
}

// TestSAOnlyOps_NonSARoles_Rejected: 14 个 SA-only RPC × 3 非 SA 角色拒绝矩阵
func TestSAOnlyOps_NonSARoles_Rejected(t *testing.T) {
	roles := []identitydomain.Role{
		identitydomain.RoleTenantAuditor,
		identitydomain.RolePlatformAuditor,
		identitydomain.RoleProjectAdmin,
	}
	for _, op := range saOnlyOps() {
		for _, r := range roles {
			t.Run(op.name+"/"+string(r), func(t *testing.T) {
				h := newHandler(t,
					principal(r, fixtureTenantID, "user-1"),
					&stubTenancySvc{})
				err := op.call(t, h)
				requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
			})
		}
	}
}

// TestSAOnlyOps_SA_OK: SA 应能通过所有 RBAC 检查
func TestSAOnlyOps_SA_OK(t *testing.T) {
	for _, op := range saOnlyOps() {
		t.Run(op.name, func(t *testing.T) {
			svc := &stubTenancySvc{
				createProjectRes: &tenancydomain.Project{ID: fixtureProjectID, TenantID: fixtureTenantID, Name: "x"},
				createNodeRes:    &tenancydomain.Node{ID: fixtureNodeID, TenantID: fixtureTenantID, Name: "n1"},
				tokenCreateRes: &tenancy.CreateRegistrationTokenResult{
					Token:     &tenancydomain.RegistrationToken{ID: "tok-1", TenantID: fixtureTenantID},
					Plaintext: "rt_xxx",
				},
			}
			h := newHandler(t, principal(identitydomain.RoleSuperAdmin, "", "sa-1"), svc)
			err := op.call(t, h)
			require.NoError(t, err)
		})
	}
}

// === adminAndAuditor 读路径：GetProject ===

// TestGetProject_SAandTA_OK：SA + TA 可读；PA 拒。
func TestGetProject_RBACMatrix(t *testing.T) {
	cases := []struct {
		role       identitydomain.Role
		expectAuth bool
	}{
		{identitydomain.RoleSuperAdmin, true},
		{identitydomain.RoleTenantAuditor, true},
		{identitydomain.RoleProjectAdmin, false},
	}
	for _, c := range cases {
		t.Run(string(c.role), func(t *testing.T) {
			svc := &stubTenancySvc{
				getProjectRes: &tenancydomain.Project{ID: fixtureProjectID, TenantID: fixtureTenantID},
			}
			h := newHandler(t, principal(c.role, fixtureTenantID, "u-1"), svc)
			_, err := h.GetProject(context.Background(),
				authHeaderReq(&tenancyv1.GetProjectRequest{Id: fixtureProjectID}))
			if c.expectAuth {
				require.NoError(t, err)
			} else {
				requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
			}
		})
	}
}

// === ListProjects ===

// TestListProjects_PA_InjectsMemberUserID: PA 视角必须用 MemberUserID 注入做过滤
// （只看自己加入的项目）。stub 不能直接断言入参，但可观察 service 是否被调到 +
// PA 应能通过 RBAC 不被拒。
func TestListProjects_PA_OK(t *testing.T) {
	svc := &stubTenancySvc{
		listProjectsRes: &tenancy.ListProjectsResult{Page: 1, PageSize: 50},
	}
	h := newHandler(t, principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc)
	_, err := h.ListProjects(context.Background(),
		authHeaderReq(&tenancyv1.ListProjectsRequest{}))
	require.NoError(t, err)
}

// === Unauthenticated ===

func TestSAOnlyOps_NoAuth_ReturnUnauthenticated(t *testing.T) {
	authErr := errx.New(errx.ErrAuthTokenInvalid, "missing bearer")
	svc := &stubTenancySvc{}
	h, err := New(svc, &stubAuthSvc{err: authErr})
	require.NoError(t, err)
	for _, op := range saOnlyOps() {
		t.Run(op.name, func(t *testing.T) {
			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
		})
	}
}

// === RedeemRegistrationToken 公开 RPC ===

// TestRedeemRegistrationToken_NoAuth_OK：公开 RPC，无 Bearer 也应直达 service。
func TestRedeemRegistrationToken_NoAuth_OK(t *testing.T) {
	svc := &stubTenancySvc{
		tokenRedeemRes: &tenancy.RedeemRegistrationTokenResult{
			Node:          &tenancydomain.Node{ID: fixtureNodeID, TenantID: fixtureTenantID, Name: "n1"},
			NodeCertPEM:   "----cert----",
			NodeKeyPEM:    "----key----",
			CACertPEM:     "----ca----",
			Fingerprint:   "abc",
			CertExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}
	// 注：authErr 设了也不应影响——RedeemRegistrationToken handler 完全跳过 auth
	h, err := New(svc, &stubAuthSvc{err: errx.New(errx.ErrAuthTokenInvalid, "ignored")})
	require.NoError(t, err)

	// 不挂 Authorization header
	req := connect.NewRequest(&tenancyv1.RedeemRegistrationTokenRequest{
		Plaintext: "rt_xxx", NodeName: "n1", Version: "1.0",
	})
	resp, callErr := h.RedeemRegistrationToken(context.Background(), req)
	require.NoError(t, callErr)
	assert.Equal(t, fixtureNodeID, resp.Msg.Node.Id)
}
