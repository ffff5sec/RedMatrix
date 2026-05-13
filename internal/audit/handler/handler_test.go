// audit/handler/handler_test.go PR-S46-A —— audit handler RBAC + BOLA 测试。
//
// 矩阵：
//   - ListLogs / GetLog / VerifyChain：SA / TenantAuditor / PlatformAuditor OK；
//     ProjectAdmin（写权限角色）应被 RequireRole(saOnly...) 拒（其实 saOnly
//     里含 TA + PA-Audit 是"只读读权限组"，PA = ProjectAdmin 拒）
//   - GetLog TA 跨租户返 ErrAuditLogNotFound（不暴露存在性）
//   - 401 路径：AuthenticateBearer 失败时全部 RPC 都返 Unauthenticated
package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auditv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/audit/v1"
	"github.com/ffff5sec/RedMatrix/internal/audit"
	auditdomain "github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// === stubs ===

type stubAuditSvc struct {
	listRes   *audit.ListLogsResult
	getRes    *auditdomain.AuditLog
	verifyRes *audit.VerifyChainResult
	err       error
}

func (s *stubAuditSvc) Log(_ context.Context, _ audit.LogEvent) error { return s.err }
func (s *stubAuditSvc) GetLog(_ context.Context, _ string) (*auditdomain.AuditLog, error) {
	return s.getRes, s.err
}
func (s *stubAuditSvc) ListLogs(_ context.Context, _ audit.ListLogsRequest) (*audit.ListLogsResult, error) {
	return s.listRes, s.err
}
func (s *stubAuditSvc) VerifyChain(_ context.Context, _ audit.VerifyChainRequest) (*audit.VerifyChainResult, error) {
	return s.verifyRes, s.err
}

var _ audit.Service = (*stubAuditSvc)(nil)

// stubAuthSvc 实现 auth.Service 的最小子集（仅 AuthenticateBearer 行为可控）。
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

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubAuditSvc) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ})
	require.NoError(t, err)
	return h
}

// === ListLogs RBAC ===

func TestListLogs_RBAC(t *testing.T) {
	t.Run("SA OK", func(t *testing.T) {
		p := principal(identitydomain.RoleSuperAdmin, "T1", "sa-1")
		h := newHandler(t, p, &stubAuditSvc{listRes: &audit.ListLogsResult{Page: 1, PageSize: 50}})
		_, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
		require.NoError(t, err)
	})

	t.Run("TenantAuditor OK", func(t *testing.T) {
		p := principal(identitydomain.RoleTenantAuditor, "T1", "ta-1")
		h := newHandler(t, p, &stubAuditSvc{listRes: &audit.ListLogsResult{Page: 1, PageSize: 50}})
		_, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
		require.NoError(t, err)
	})

	t.Run("PlatformAuditor OK", func(t *testing.T) {
		p := principal(identitydomain.RolePlatformAuditor, "", "pa-aud-1")
		h := newHandler(t, p, &stubAuditSvc{listRes: &audit.ListLogsResult{Page: 1, PageSize: 50}})
		_, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
		require.NoError(t, err)
	})

	t.Run("ProjectAdmin rejected", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, "T1", "pa-1")
		h := newHandler(t, p, &stubAuditSvc{})
		_, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
		requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
	})
}

// === GetLog RBAC + BOLA ===

func TestGetLog_TenantAuditorCrossTenant_ReturnsNotFound(t *testing.T) {
	p := principal(identitydomain.RoleTenantAuditor, "T1", "ta-1")
	// 服务层返了另一个 tenant 的 audit 行
	row := &auditdomain.AuditLog{
		ID: "audit-1", TenantID: "T-OTHER",
		Action: auditdomain.ActionLogin, ResourceKind: "session",
	}
	h := newHandler(t, p, &stubAuditSvc{getRes: row})

	_, err := h.GetLog(context.Background(),
		authHeaderReq(&auditv1.GetLogRequest{Id: "audit-1"}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrAuditLogNotFound)
}

func TestGetLog_TenantAuditorSameTenant_OK(t *testing.T) {
	p := principal(identitydomain.RoleTenantAuditor, "T1", "ta-1")
	row := &auditdomain.AuditLog{
		ID: "audit-1", TenantID: "T1",
		Action: auditdomain.ActionLogin, ResourceKind: "session",
	}
	h := newHandler(t, p, &stubAuditSvc{getRes: row})
	_, err := h.GetLog(context.Background(),
		authHeaderReq(&auditv1.GetLogRequest{Id: "audit-1"}))
	require.NoError(t, err)
}

func TestGetLog_PlatformAuditorCrossTenant_OK(t *testing.T) {
	// PA-Audit 跨租户可读（设计如此 — HLD: PlatformAuditor = 跨租户审计员）
	p := principal(identitydomain.RolePlatformAuditor, "", "pa-aud-1")
	row := &auditdomain.AuditLog{
		ID: "audit-1", TenantID: "T-OTHER",
		Action: auditdomain.ActionLogin, ResourceKind: "session",
	}
	h := newHandler(t, p, &stubAuditSvc{getRes: row})
	_, err := h.GetLog(context.Background(),
		authHeaderReq(&auditv1.GetLogRequest{Id: "audit-1"}))
	require.NoError(t, err)
}

func TestGetLog_ProjectAdmin_Rejected(t *testing.T) {
	p := principal(identitydomain.RoleProjectAdmin, "T1", "pa-1")
	h := newHandler(t, p, &stubAuditSvc{})
	_, err := h.GetLog(context.Background(),
		authHeaderReq(&auditv1.GetLogRequest{Id: "audit-1"}))
	requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
}

// === VerifyChain RBAC ===

func TestVerifyChain_RBAC(t *testing.T) {
	cases := []struct {
		name        string
		role        identitydomain.Role
		expectAllow bool
	}{
		{"SA OK", identitydomain.RoleSuperAdmin, true},
		{"TenantAuditor OK", identitydomain.RoleTenantAuditor, true},
		{"PlatformAuditor OK", identitydomain.RolePlatformAuditor, true},
		{"ProjectAdmin rejected", identitydomain.RoleProjectAdmin, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := principal(c.role, "T1", "user-1")
			h := newHandler(t, p, &stubAuditSvc{
				verifyRes: &audit.VerifyChainResult{OK: true, Total: 5},
			})
			_, err := h.VerifyChain(context.Background(),
				authHeaderReq(&auditv1.VerifyChainRequest{Limit: 100}))
			if c.expectAllow {
				require.NoError(t, err)
			} else {
				requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
			}
		})
	}
}

// === Unauthenticated ===

func TestAllRPCs_NoAuth_ReturnUnauthenticated(t *testing.T) {
	authErr := errx.New(errx.ErrAuthTokenInvalid, "missing bearer")
	svc := &stubAuditSvc{}
	h, err := New(svc, &stubAuthSvc{err: authErr})
	require.NoError(t, err)

	t.Run("ListLogs", func(t *testing.T) {
		_, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
		requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
	})
	t.Run("GetLog", func(t *testing.T) {
		_, err := h.GetLog(context.Background(), authHeaderReq(&auditv1.GetLogRequest{Id: "x"}))
		requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
	})
	t.Run("VerifyChain", func(t *testing.T) {
		_, err := h.VerifyChain(context.Background(), authHeaderReq(&auditv1.VerifyChainRequest{}))
		requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
	})
}

// === ListLogs proto conversion smoke ===

// TestListLogs_ProtoConv 烟雾测试：service 返一条 audit 行；handler proto 转回字段对齐。
func TestListLogs_ProtoConv(t *testing.T) {
	p := principal(identitydomain.RoleSuperAdmin, "T1", "sa-1")
	uid := "u-1"
	pid := "p-1"
	row := &auditdomain.AuditLog{
		ID: "id-1", TenantID: "T1", ActorUserID: &uid, ProjectID: &pid,
		Action: auditdomain.ActionLogin, ResourceKind: "session",
		PrevHash: "00", Hash: "ff", CreatedAt: time.Now(),
		Payload: map[string]any{"result": "success"},
	}
	h := newHandler(t, p, &stubAuditSvc{
		listRes: &audit.ListLogsResult{Logs: []*auditdomain.AuditLog{row}, Total: 1, Page: 1, PageSize: 50},
	})
	res, err := h.ListLogs(context.Background(), authHeaderReq(&auditv1.ListLogsRequest{}))
	require.NoError(t, err)
	require.Len(t, res.Msg.Logs, 1)
	got := res.Msg.Logs[0]
	assert.Equal(t, "id-1", got.Id)
	assert.Equal(t, "T1", got.TenantId)
	assert.Equal(t, "u-1", got.ActorUserId)
	assert.Equal(t, "p-1", got.ProjectId)
	assert.Equal(t, string(auditdomain.ActionLogin), got.Action)
}
