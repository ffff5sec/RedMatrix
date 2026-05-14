// asset/handler/handler_test.go PR-S46-D —— asset handler RBAC + BOLA test.
//
// 矩阵：
//   - ListAssets RBAC 注入：
//     · SA / PlatformAuditor: ScopedTenantID + ScopedProjectIDs 均空
//     · TenantAuditor:        ScopedTenantID = caller.TenantID
//     · ProjectAdmin:         ScopedTenantID + ScopedProjectIDs = memberDB.list
//     · ProjectAdmin nil memberDB → Internal
//   - GetAsset BOLA:
//     · TA 跨租户访问返 AssetNotFound（不暴露）
//     · PA 不在项目成员返 AssetNotFound
//     · PA 命中项目放行
//     · SA / PA-Audit 跨租户放行
package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	assetv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/asset/v1"
	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// === stubs ===

type stubAssetSvc struct {
	listRes    *asset.ListResponse
	listErr    error
	getRes     *domain.Asset
	getErr     error
	lastListIn asset.ListRequest // 记录入参，断言 RBAC 注入
}

func (s *stubAssetSvc) UpsertFromResults(_ context.Context, _ []asset.ResultInput) error {
	panic("unexpected: UpsertFromResults")
}
func (s *stubAssetSvc) ListAssets(_ context.Context, req asset.ListRequest) (*asset.ListResponse, error) {
	s.lastListIn = req
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.listRes, nil
}
func (s *stubAssetSvc) GetAsset(_ context.Context, _ string) (*domain.Asset, error) {
	return s.getRes, s.getErr
}
func (s *stubAssetSvc) SweepDisappeared(_ context.Context, _ time.Duration) (int, error) {
	return 0, nil
}
func (s *stubAssetSvc) SweepCertsExpiring(_ context.Context, _, _ time.Duration) (int, error) {
	return 0, nil
}

var _ asset.Service = (*stubAssetSvc)(nil)

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
	fixtureAssetID   = "asset-1"
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

func assetFixture() *domain.Asset {
	return &domain.Asset{
		ID:        fixtureAssetID,
		TenantID:  fixtureTenantID,
		ProjectID: fixtureProjectID,
		Kind:      domain.KindHost,
		Value:     "192.0.2.1",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
	}
}

func newHandler(t *testing.T, princ *auth.UserPrincipal, svc *stubAssetSvc, mem MembershipLookup) *Handler {
	t.Helper()
	h, err := New(svc, &stubAuthSvc{princ: princ}, mem)
	require.NoError(t, err)
	return h
}

// === ListAssets RBAC scope 注入 ===

func TestListAssets_SA_NoScopeInjected(t *testing.T) {
	svc := &stubAssetSvc{listRes: &asset.ListResponse{Page: 1, PageSize: 50}}
	h := newHandler(t, principal(identitydomain.RoleSuperAdmin, "", "sa-1"), svc, nil)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	require.NoError(t, err)
	assert.Empty(t, svc.lastListIn.ScopedTenantID, "SA 不注 ScopedTenantID")
	assert.Nil(t, svc.lastListIn.ScopedProjectIDs, "SA 不注 ScopedProjectIDs")
}

func TestListAssets_PlatformAuditor_NoScopeInjected(t *testing.T) {
	svc := &stubAssetSvc{listRes: &asset.ListResponse{Page: 1, PageSize: 50}}
	h := newHandler(t,
		principal(identitydomain.RolePlatformAuditor, "", "pa-aud-1"), svc, nil)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	require.NoError(t, err)
	assert.Empty(t, svc.lastListIn.ScopedTenantID)
	assert.Nil(t, svc.lastListIn.ScopedProjectIDs)
}

func TestListAssets_TA_InjectsScopedTenantID(t *testing.T) {
	svc := &stubAssetSvc{listRes: &asset.ListResponse{Page: 1, PageSize: 50}}
	h := newHandler(t,
		principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"), svc, nil)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	require.NoError(t, err)
	assert.Equal(t, fixtureTenantID, svc.lastListIn.ScopedTenantID)
	assert.Nil(t, svc.lastListIn.ScopedProjectIDs, "TA 不注 ProjectIDs，跨项目可见")
}

func TestListAssets_PA_InjectsBothScopes(t *testing.T) {
	svc := &stubAssetSvc{listRes: &asset.ListResponse{Page: 1, PageSize: 50}}
	mem := &stubMemberDB{ids: []string{"p-a", "p-b"}}
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	require.NoError(t, err)
	assert.Equal(t, fixtureTenantID, svc.lastListIn.ScopedTenantID)
	assert.Equal(t, []string{"p-a", "p-b"}, svc.lastListIn.ScopedProjectIDs)
}

// TestListAssets_PA_EmptyMembershipInjectsEmptySlice 验证 PA 0 项目时
// 注入空切片（非 nil），让 service 走"返空页"短路而非"不限"。
func TestListAssets_PA_EmptyMembershipInjectsEmptySlice(t *testing.T) {
	svc := &stubAssetSvc{listRes: &asset.ListResponse{Page: 1, PageSize: 50}}
	mem := &stubMemberDB{ids: nil}
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, mem)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	require.NoError(t, err)
	require.NotNil(t, svc.lastListIn.ScopedProjectIDs, "0 项目时必须传空切片，不是 nil")
	assert.Len(t, svc.lastListIn.ScopedProjectIDs, 0)
}

func TestListAssets_PA_NilMemberDB_Internal(t *testing.T) {
	svc := &stubAssetSvc{}
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"), svc, nil)
	_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
	requireConnectCode(t, err, connect.CodeInternal, errx.ErrInternal)
}

// === GetAsset BOLA ===

func TestGetAsset_TACrossTenant_ReturnsNotFound(t *testing.T) {
	a := assetFixture()
	a.TenantID = "T-OTHER"
	h := newHandler(t,
		principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1"),
		&stubAssetSvc{getRes: a}, nil)
	_, err := h.GetAsset(context.Background(),
		authHeaderReq(&assetv1.GetAssetRequest{Id: fixtureAssetID}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrAssetNotFound)
}

func TestGetAsset_PAProjectMatch_OK(t *testing.T) {
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"),
		&stubAssetSvc{getRes: assetFixture()},
		&stubMemberDB{ids: []string{fixtureProjectID}})
	_, err := h.GetAsset(context.Background(),
		authHeaderReq(&assetv1.GetAssetRequest{Id: fixtureAssetID}))
	require.NoError(t, err)
}

func TestGetAsset_PAProjectMiss_ReturnsNotFound(t *testing.T) {
	h := newHandler(t,
		principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1"),
		&stubAssetSvc{getRes: assetFixture()},
		&stubMemberDB{ids: []string{"p-other"}})
	_, err := h.GetAsset(context.Background(),
		authHeaderReq(&assetv1.GetAssetRequest{Id: fixtureAssetID}))
	requireConnectCode(t, err, connect.CodeNotFound, errx.ErrAssetNotFound)
}

func TestGetAsset_SACrossTenant_OK(t *testing.T) {
	a := assetFixture()
	a.TenantID = "T-OTHER"
	h := newHandler(t,
		principal(identitydomain.RoleSuperAdmin, "", "sa-1"),
		&stubAssetSvc{getRes: a}, nil)
	_, err := h.GetAsset(context.Background(),
		authHeaderReq(&assetv1.GetAssetRequest{Id: fixtureAssetID}))
	require.NoError(t, err)
}

// === Unauthenticated ===

func TestAllRPCs_NoAuth_ReturnUnauthenticated(t *testing.T) {
	authErr := errx.New(errx.ErrAuthTokenInvalid, "missing bearer")
	svc := &stubAssetSvc{}
	h, err := New(svc, &stubAuthSvc{err: authErr}, nil)
	require.NoError(t, err)

	t.Run("ListAssets", func(t *testing.T) {
		_, err := h.ListAssets(context.Background(), authHeaderReq(&assetv1.ListAssetsRequest{}))
		requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
	})
	t.Run("GetAsset", func(t *testing.T) {
		_, err := h.GetAsset(context.Background(),
			authHeaderReq(&assetv1.GetAssetRequest{Id: "x"}))
		requireConnectCode(t, err, connect.CodeUnauthenticated, errx.ErrAuthTokenInvalid)
	})
}
