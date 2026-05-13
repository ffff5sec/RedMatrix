// pluginpkg/handler/handler_test.go PR-S46-B —— pluginpkg handler RBAC test.
//
// 矩阵：
//   - SA-only RPC：UploadPackage / SetPackageActive / DeprecatePackage /
//     RevokeSigningKey。SA OK；TA / PA-Audit / ProjectAdmin 均拒。
//   - allRoles 读路径：ListPackages 烟雾覆盖 4 角色均可访问。
//   - 401：AuthenticateBearer 失败时全部 RPC 都返 Unauthenticated。
package handler

import (
	"context"
	"net/url"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pluginv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/pluginpkg/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg"
	plugindomain "github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// === stubs ===

// stubPluginSvc 实现 pluginpkg.Service：返预设值或 panic（未配置默认 panic 表示路径未到达）。
type stubPluginSvc struct {
	uploadRes   *plugindomain.PluginPackage
	uploadErr   error
	listRes     *pluginpkg.ListResult
	getRes      *plugindomain.PluginPackage
	latestRes   *plugindomain.PluginPackage
	downloadURL string
	downloadExp time.Time
	signingKeys []*plugindomain.SigningKey
	registerRes *plugindomain.SigningKey
	defaultErr  error
}

func (s *stubPluginSvc) UploadPackage(_ context.Context, _ pluginpkg.UploadRequest) (*plugindomain.PluginPackage, error) {
	if s.uploadErr != nil {
		return nil, s.uploadErr
	}
	return s.uploadRes, nil
}
func (s *stubPluginSvc) ListPackages(_ context.Context, _ pluginpkg.ListRequest) (*pluginpkg.ListResult, error) {
	return s.listRes, s.defaultErr
}
func (s *stubPluginSvc) GetPackage(_ context.Context, _ string) (*plugindomain.PluginPackage, error) {
	return s.getRes, s.defaultErr
}
func (s *stubPluginSvc) GetLatestVersion(_ context.Context, _, _ string) (*plugindomain.PluginPackage, error) {
	return s.latestRes, s.defaultErr
}
func (s *stubPluginSvc) GetDownloadURL(_ context.Context, _ string) (string, time.Time, error) {
	return s.downloadURL, s.downloadExp, s.defaultErr
}
func (s *stubPluginSvc) SetActive(_ context.Context, _ string, _ bool) error {
	return s.defaultErr
}
func (s *stubPluginSvc) DeprecatePackage(_ context.Context, _ string) error {
	return s.defaultErr
}
func (s *stubPluginSvc) ListSigningKeys(_ context.Context) ([]*plugindomain.SigningKey, error) {
	return s.signingKeys, s.defaultErr
}
func (s *stubPluginSvc) RegisterSigningKey(_ context.Context, _ *plugindomain.SigningKey) (*plugindomain.SigningKey, error) {
	return s.registerRes, s.defaultErr
}
func (s *stubPluginSvc) RevokeSigningKey(_ context.Context, _ string) error {
	return s.defaultErr
}

var _ pluginpkg.Service = (*stubPluginSvc)(nil)

// stubAuthSvc — 与其它 handler 测试一致的最小 auth stub。
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

func principal(role identitydomain.Role) *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID: "u-1", TenantID: "T1", Username: "tester", Role: role,
		Source: auth.PrincipalSourceJWT,
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

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubPluginSvc) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ})
	require.NoError(t, err)
	return h
}

// === SA-only 矩阵 ===

// saOnlyOp 描述一个 SA-only RPC 的最小调用 helper。
type saOnlyOp struct {
	name string
	call func(t *testing.T, h *Handler) error
}

func saOnlyOps() []saOnlyOp {
	return []saOnlyOp{
		{
			name: "UploadPackage",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.UploadPackage(context.Background(),
					authHeaderReq(&pluginv1.UploadPackageRequest{
						Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: []byte("z"),
					}))
				return err
			},
		},
		{
			name: "SetPackageActive",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.SetPackageActive(context.Background(),
					authHeaderReq(&pluginv1.SetPackageActiveRequest{Id: "p-1", Active: true}))
				return err
			},
		},
		{
			name: "DeprecatePackage",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.DeprecatePackage(context.Background(),
					authHeaderReq(&pluginv1.DeprecatePackageRequest{Id: "p-1"}))
				return err
			},
		},
		{
			name: "RevokeSigningKey",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.RevokeSigningKey(context.Background(),
					authHeaderReq(&pluginv1.RevokeSigningKeyRequest{KeyId: "k-1"}))
				return err
			},
		},
	}
}

// TestSAOnlyOps_NonSARoles_Rejected PR-S46：所有 SA-only RPC 必须拒
// TA / PlatformAuditor / ProjectAdmin。
func TestSAOnlyOps_NonSARoles_Rejected(t *testing.T) {
	roles := []identitydomain.Role{
		identitydomain.RoleTenantAuditor,
		identitydomain.RolePlatformAuditor,
		identitydomain.RoleProjectAdmin,
	}
	for _, op := range saOnlyOps() {
		for _, r := range roles {
			t.Run(op.name+"/"+string(r), func(t *testing.T) {
				h := newHandler(t, principal(r), &stubPluginSvc{})
				err := op.call(t, h)
				requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
			})
		}
	}
}

// TestSAOnlyOps_SA_OK PR-S46：SA 应能通过 RBAC（service 返成功即通过）。
func TestSAOnlyOps_SA_OK(t *testing.T) {
	for _, op := range saOnlyOps() {
		t.Run(op.name, func(t *testing.T) {
			svc := &stubPluginSvc{
				uploadRes: &plugindomain.PluginPackage{
					ID: "p-1", Slug: "x", Version: "v1", Platform: plugindomain.PlatformLinuxAMD64,
				},
			}
			h := newHandler(t, principal(identitydomain.RoleSuperAdmin), svc)
			err := op.call(t, h)
			require.NoError(t, err)
		})
	}
}

// === allRoles 读路径烟雾测试 ===

// TestListPackages_AllRoles_OK 验证读路径不拒 4 角色任一。
func TestListPackages_AllRoles_OK(t *testing.T) {
	roles := []identitydomain.Role{
		identitydomain.RoleSuperAdmin,
		identitydomain.RoleTenantAuditor,
		identitydomain.RolePlatformAuditor,
		identitydomain.RoleProjectAdmin,
	}
	for _, r := range roles {
		t.Run(string(r), func(t *testing.T) {
			svc := &stubPluginSvc{
				listRes: &pluginpkg.ListResult{Packages: nil, Total: 0, Page: 1, PageSize: 50},
			}
			h := newHandler(t, principal(r), svc)
			_, err := h.ListPackages(context.Background(),
				authHeaderReq(&pluginv1.ListPackagesRequest{}))
			require.NoError(t, err)
		})
	}
}

// TestGetDownloadURL_AllRoles_OK presigned URL 路径任一角色可调（service 校 active/deprecated）。
func TestGetDownloadURL_AllRoles_OK(t *testing.T) {
	expiresAt := time.Now().Add(15 * time.Minute)
	u, _ := url.Parse("https://example.test/a?sig=x")
	svc := &stubPluginSvc{downloadURL: u.String(), downloadExp: expiresAt}
	h := newHandler(t, principal(identitydomain.RoleProjectAdmin), svc)
	_, err := h.GetDownloadURL(context.Background(),
		authHeaderReq(&pluginv1.GetDownloadURLRequest{Id: "p-1"}))
	require.NoError(t, err)
}

// === Unauthenticated ===

func TestAllRPCs_NoAuth_ReturnUnauthenticated(t *testing.T) {
	authErr := errx.New(errx.ErrAuthTokenInvalid, "missing bearer")
	svc := &stubPluginSvc{}
	h, err := New(svc, &stubAuthSvc{err: authErr})
	require.NoError(t, err)

	cases := []struct {
		name string
		call func() error
	}{
		{"UploadPackage", func() error {
			_, err := h.UploadPackage(context.Background(),
				authHeaderReq(&pluginv1.UploadPackageRequest{}))
			return err
		}},
		{"ListPackages", func() error {
			_, err := h.ListPackages(context.Background(),
				authHeaderReq(&pluginv1.ListPackagesRequest{}))
			return err
		}},
		{"GetDownloadURL", func() error {
			_, err := h.GetDownloadURL(context.Background(),
				authHeaderReq(&pluginv1.GetDownloadURLRequest{Id: "p-1"}))
			return err
		}},
		{"SetPackageActive", func() error {
			_, err := h.SetPackageActive(context.Background(),
				authHeaderReq(&pluginv1.SetPackageActiveRequest{Id: "p-1"}))
			return err
		}},
		{"DeprecatePackage", func() error {
			_, err := h.DeprecatePackage(context.Background(),
				authHeaderReq(&pluginv1.DeprecatePackageRequest{Id: "p-1"}))
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
