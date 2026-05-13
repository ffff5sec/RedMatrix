// notify/handler/handler_test.go PR-S47 —— notify handler RBAC + BOLA test.
//
// 矩阵：
//   - 写路径（Create/Update/Delete/Test）writers：SA / PA OK；TA / PA-Audit 拒
//     特别覆盖 TestSubscription（发外部 webhook 出站）— 必须拒 Auditor
//   - 读路径（List/Get/ListDeliveries）allRoles：4 角色 OK
//   - BOLA assertSubVisible：TA 跨租户 SubscriptionNotFound（防枚举）
//   - PA 跨项目订阅创建：必须指定自己加入的 project；空 project_id 拒
package handler

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	notifyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/notify/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/notify"
	notifydomain "github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// === stubs ===

type stubNotifySvc struct {
	createRes  *notifydomain.Subscription
	getRes     *notifydomain.Subscription
	listRes    *notify.ListSubscriptionsResult
	updateRes  *notifydomain.Subscription
	listDelRes *notify.ListDeliveriesResult
	defaultErr error
}

func (s *stubNotifySvc) CreateSubscription(_ context.Context, _ notify.CreateSubscriptionRequest) (*notifydomain.Subscription, error) {
	return s.createRes, s.defaultErr
}
func (s *stubNotifySvc) GetSubscription(_ context.Context, _ string) (*notifydomain.Subscription, error) {
	return s.getRes, s.defaultErr
}
func (s *stubNotifySvc) ListSubscriptions(_ context.Context, _ notify.ListSubscriptionsRequest) (*notify.ListSubscriptionsResult, error) {
	return s.listRes, s.defaultErr
}
func (s *stubNotifySvc) UpdateSubscription(_ context.Context, _ notify.UpdateSubscriptionRequest) (*notifydomain.Subscription, error) {
	return s.updateRes, s.defaultErr
}
func (s *stubNotifySvc) DeleteSubscription(_ context.Context, _ string) error { return s.defaultErr }
func (s *stubNotifySvc) ListDeliveries(_ context.Context, _ notify.ListDeliveriesRequest) (*notify.ListDeliveriesResult, error) {
	return s.listDelRes, s.defaultErr
}
func (s *stubNotifySvc) Notify(_ context.Context, _ notify.Event) error {
	panic("unexpected: Notify")
}
func (s *stubNotifySvc) TestSubscription(_ context.Context, _ string) error { return s.defaultErr }

var _ notify.Service = (*stubNotifySvc)(nil)

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
	fixtureSubID     = "sub-1"
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

func subFixture(projectID string) *notifydomain.Subscription {
	pid := projectID
	return &notifydomain.Subscription{
		ID: fixtureSubID, TenantID: fixtureTenantID, ProjectID: &pid,
		Name: "test-sub", Channel: notifydomain.ChannelWebhook, Enabled: true,
	}
}

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubNotifySvc, mem MembershipLookup) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ}, mem)
	require.NoError(t, err)
	return h
}

// === 写路径矩阵：writers (SA+PA) ===

type writeOp struct {
	name string
	call func(t *testing.T, h *Handler) error
}

func writeOps() []writeOp {
	return []writeOp{
		{
			name: "CreateSubscription",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.CreateSubscription(context.Background(),
					authHeaderReq(&notifyv1.CreateSubscriptionRequest{
						ProjectId: fixtureProjectID, Name: "x", Channel: "webhook",
						EventKinds: []string{"task_completed"},
					}))
				return err
			},
		},
		{
			name: "UpdateSubscription",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.UpdateSubscription(context.Background(),
					authHeaderReq(&notifyv1.UpdateSubscriptionRequest{
						Id: fixtureSubID, Name: "x", Channel: "webhook",
						EventKinds: []string{"task_completed"},
					}))
				return err
			},
		},
		{
			name: "DeleteSubscription",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.DeleteSubscription(context.Background(),
					authHeaderReq(&notifyv1.DeleteSubscriptionRequest{Id: fixtureSubID}))
				return err
			},
		},
		{
			name: "TestSubscription",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.TestSubscription(context.Background(),
					authHeaderReq(&notifyv1.TestSubscriptionRequest{Id: fixtureSubID}))
				return err
			},
		},
	}
}

// TestWriteOps_AuditorRoles_Rejected: TA / PA-Audit 都不能写订阅
// 特别 TestSubscription —— 发外部 webhook 出站 = 写操作，必须拒。
func TestWriteOps_AuditorRoles_Rejected(t *testing.T) {
	for _, op := range writeOps() {
		t.Run(op.name+"/TA", func(t *testing.T) {
			h := newHandler(t,
				principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"),
				&stubNotifySvc{}, nil)
			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
		})
		t.Run(op.name+"/PlatformAuditor", func(t *testing.T) {
			h := newHandler(t,
				principal(identitydomain.RolePlatformAuditor, "", "pa-aud-1"),
				&stubNotifySvc{}, nil)
			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
		})
	}
}

// TestWriteOps_SA_PA_OK: SA / PA 写路径放行。
func TestWriteOps_SA_PA_OK(t *testing.T) {
	for _, op := range writeOps() {
		t.Run(op.name+"/SA", func(t *testing.T) {
			svc := &stubNotifySvc{
				createRes: subFixture(fixtureProjectID),
				updateRes: subFixture(fixtureProjectID),
				getRes:    subFixture(fixtureProjectID),
			}
			h := newHandler(t, principal(identitydomain.RoleSuperAdmin, "", "sa-1"), svc, nil)
			err := op.call(t, h)
			require.NoError(t, err)
		})
		t.Run(op.name+"/PA", func(t *testing.T) {
			svc := &stubNotifySvc{
				createRes: subFixture(fixtureProjectID),
				updateRes: subFixture(fixtureProjectID),
				getRes:    subFixture(fixtureProjectID),
			}
			mem := &stubMemberDB{ids: []string{fixtureProjectID}}
			h := newHandler(t,
				principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
			err := op.call(t, h)
			require.NoError(t, err)
		})
	}
}

// === 读路径全角色 ===

func TestListSubscriptions_AllRoles_OK(t *testing.T) {
	roles := []identitydomain.Role{
		identitydomain.RoleSuperAdmin,
		identitydomain.RoleTenantAuditor,
		identitydomain.RolePlatformAuditor,
		identitydomain.RoleProjectAdmin,
	}
	for _, r := range roles {
		t.Run(string(r), func(t *testing.T) {
			svc := &stubNotifySvc{
				listRes: &notify.ListSubscriptionsResult{Page: 1, PageSize: 50},
			}
			h := newHandler(t, principal(r, fixtureTenantID, "u-1"), svc, nil)
			_, err := h.ListSubscriptions(context.Background(),
				authHeaderReq(&notifyv1.ListSubscriptionsRequest{}))
			require.NoError(t, err)
		})
	}
}

// === BOLA assertSubVisible ===

// TestGetSubscription_TACrossTenant_ReturnsNotFound: TA 调 Get 看跨租户 sub
// 返 ChannelNotFound（防枚举）。
func TestGetSubscription_TACrossTenant_ReturnsNotFound(t *testing.T) {
	sub := subFixture(fixtureProjectID)
	sub.TenantID = "T-OTHER"
	h := newHandler(t,
		principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"),
		&stubNotifySvc{getRes: sub}, nil)
	_, err := h.GetSubscription(context.Background(),
		authHeaderReq(&notifyv1.GetSubscriptionRequest{Id: fixtureSubID}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrChannelNotFound)
}

// === assertProjectMember：PA 创建跨项目订阅必拒 ===

// TestCreateSubscription_PA_EmptyProjectID_Rejected: PA 必须指定 project_id；
// 空 project_id（=跨项目订阅）违反 PA 只能管自己项目的语义。
func TestCreateSubscription_PA_EmptyProjectID_Rejected(t *testing.T) {
	svc := &stubNotifySvc{createRes: subFixture("")}
	mem := &stubMemberDB{ids: []string{fixtureProjectID}}
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
	_, err := h.CreateSubscription(context.Background(),
		authHeaderReq(&notifyv1.CreateSubscriptionRequest{
			ProjectId: "", // PA 不能创建跨项目订阅
			Name:      "x", Channel: "webhook",
		}))
	requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzNotProjectMember)
}

// TestCreateSubscription_PA_NotMemberOfProject_Rejected: PA 指定的 project_id
// 不在加入列表里 → 拒。
func TestCreateSubscription_PA_NotMemberOfProject_Rejected(t *testing.T) {
	svc := &stubNotifySvc{createRes: subFixture(fixtureProjectID)}
	mem := &stubMemberDB{ids: []string{"p-other"}}
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
	_, err := h.CreateSubscription(context.Background(),
		authHeaderReq(&notifyv1.CreateSubscriptionRequest{
			ProjectId: fixtureProjectID, Name: "x", Channel: "webhook",
		}))
	requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzNotProjectMember)
}

// === Unauthenticated ===

func TestAllRPCs_NoAuth_ReturnUnauthenticated(t *testing.T) {
	authErr := errx.New(errx.ErrAuthTokenInvalid, "missing bearer")
	svc := &stubNotifySvc{}
	h, err := New(svc, &stubAuthSvc{err: authErr}, nil)
	require.NoError(t, err)

	cases := []struct {
		name string
		call func() error
	}{
		{"CreateSubscription", func() error {
			_, err := h.CreateSubscription(context.Background(),
				authHeaderReq(&notifyv1.CreateSubscriptionRequest{}))
			return err
		}},
		{"ListSubscriptions", func() error {
			_, err := h.ListSubscriptions(context.Background(),
				authHeaderReq(&notifyv1.ListSubscriptionsRequest{}))
			return err
		}},
		{"DeleteSubscription", func() error {
			_, err := h.DeleteSubscription(context.Background(),
				authHeaderReq(&notifyv1.DeleteSubscriptionRequest{Id: "x"}))
			return err
		}},
		{"TestSubscription", func() error {
			_, err := h.TestSubscription(context.Background(),
				authHeaderReq(&notifyv1.TestSubscriptionRequest{Id: "x"}))
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
		})
	}
}
