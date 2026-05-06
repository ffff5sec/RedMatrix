package handler

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
)

// === mock auth.Service ===

type mockAuthSvc struct {
	loginRes *auth.LoginResult
	loginErr error
	loginReq auth.LoginRequest

	authBearerRes *auth.UserPrincipal
	authBearerErr error

	logoutErr     error
	logoutCalls   int
	logoutSession string

	logoutAllErr   error
	logoutAllCalls int
	logoutAllUser  string

	createRes  *auth.CreateAPIKeyResult
	createErr  error
	createReq  auth.CreateAPIKeyRequest
	listRes    []*domain.APIKey
	listErr    error
	revokeErr  error
	revokeUser string
	revokeKey  string

	getCurrentRes  *domain.User
	getCurrentErr  error
	getCurrentUser string

	changePwdErr     error
	changePwdUser    string
	changePwdCurrent string
	changePwdNew     string

	createUserRes *auth.CreateUserResult
	createUserErr error
	createUserReq auth.CreateUserRequest

	listUsersRes *auth.ListUsersResult
	listUsersErr error
	listUsersReq auth.ListUsersRequest

	getUserRes *domain.User
	getUserErr error
	getUserID  string

	enableErr      error
	disableErr     error
	resetPwdRes    string
	resetPwdErr    error
	forceLogoutErr error
	enableID       string
	disableID      string
	resetPwdID     string
	forceLogoutID  string
}

func (m *mockAuthSvc) Login(_ context.Context, req auth.LoginRequest) (*auth.LoginResult, error) {
	m.loginReq = req
	if m.loginErr != nil {
		return nil, m.loginErr
	}
	return m.loginRes, nil
}

func (m *mockAuthSvc) AuthenticateBearer(_ context.Context, _ string) (*auth.UserPrincipal, error) {
	if m.authBearerErr != nil {
		return nil, m.authBearerErr
	}
	return m.authBearerRes, nil
}

func (m *mockAuthSvc) Logout(_ context.Context, sessionID string) error {
	m.logoutCalls++
	m.logoutSession = sessionID
	return m.logoutErr
}

func (m *mockAuthSvc) LogoutAllSessions(_ context.Context, userID string) error {
	m.logoutAllCalls++
	m.logoutAllUser = userID
	return m.logoutAllErr
}

func (m *mockAuthSvc) CreateAPIKey(_ context.Context, req auth.CreateAPIKeyRequest) (*auth.CreateAPIKeyResult, error) {
	m.createReq = req
	if m.createErr != nil {
		return nil, m.createErr
	}
	return m.createRes, nil
}

func (m *mockAuthSvc) ListAPIKeys(_ context.Context, _ string) ([]*domain.APIKey, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listRes, nil
}

func (m *mockAuthSvc) RevokeAPIKey(_ context.Context, userID, keyID string) error {
	m.revokeUser = userID
	m.revokeKey = keyID
	return m.revokeErr
}

func (m *mockAuthSvc) GetCurrentUser(_ context.Context, userID string) (*domain.User, error) {
	m.getCurrentUser = userID
	if m.getCurrentErr != nil {
		return nil, m.getCurrentErr
	}
	return m.getCurrentRes, nil
}

func (m *mockAuthSvc) ChangePassword(_ context.Context, userID, current, newPwd string) error {
	m.changePwdUser = userID
	m.changePwdCurrent = current
	m.changePwdNew = newPwd
	return m.changePwdErr
}

func (m *mockAuthSvc) CreateUser(_ context.Context, req auth.CreateUserRequest) (*auth.CreateUserResult, error) {
	m.createUserReq = req
	if m.createUserErr != nil {
		return nil, m.createUserErr
	}
	return m.createUserRes, nil
}

func (m *mockAuthSvc) ListUsers(_ context.Context, req auth.ListUsersRequest) (*auth.ListUsersResult, error) {
	m.listUsersReq = req
	if m.listUsersErr != nil {
		return nil, m.listUsersErr
	}
	return m.listUsersRes, nil
}

func (m *mockAuthSvc) GetUser(_ context.Context, id string) (*domain.User, error) {
	m.getUserID = id
	if m.getUserErr != nil {
		return nil, m.getUserErr
	}
	return m.getUserRes, nil
}

func (m *mockAuthSvc) EnableUser(_ context.Context, id string) error {
	m.enableID = id
	return m.enableErr
}

func (m *mockAuthSvc) DisableUser(_ context.Context, id string) error {
	m.disableID = id
	return m.disableErr
}

func (m *mockAuthSvc) ResetPassword(_ context.Context, id string) (string, error) {
	m.resetPwdID = id
	if m.resetPwdErr != nil {
		return "", m.resetPwdErr
	}
	return m.resetPwdRes, nil
}

func (m *mockAuthSvc) ForceLogout(_ context.Context, id string) error {
	m.forceLogoutID = id
	return m.forceLogoutErr
}

// === mock captcha ===

type mockCaptcha struct {
	genErr error
	genRes policy.CaptchaChallenge
}

func (m *mockCaptcha) Generate(_ context.Context) (policy.CaptchaChallenge, error) {
	if m.genErr != nil {
		return policy.CaptchaChallenge{}, m.genErr
	}
	return m.genRes, nil
}

func (m *mockCaptcha) Verify(_ context.Context, _, _ string) (bool, error) { return true, nil }
func (m *mockCaptcha) IsRequired(_ context.Context, _ netip.Addr, _ string) bool {
	return false
}

// === fixtures ===

func bearerHeader(token string) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	return h
}

func authedPrincipal() *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID:    "u-1",
		TenantID:  "t-1",
		Username:  "alice",
		Role:      domain.RoleProjectAdmin,
		SessionID: "sess-1",
		Source:    auth.PrincipalSourceJWT,
	}
}

func superAdminPrincipal() *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID:    "u-sa",
		Username:  "admin",
		Role:      domain.RoleSuperAdmin,
		SessionID: "sess-sa",
		Source:    auth.PrincipalSourceJWT,
	}
}

func auditorPrincipal() *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID:    "u-ta",
		TenantID:  "t-1",
		Username:  "auditor",
		Role:      domain.RoleTenantAuditor,
		SessionID: "sess-ta",
		Source:    auth.PrincipalSourceJWT,
	}
}

// === New ===

func TestNew_RejectsNilService(t *testing.T) {
	_, err := New(nil, nil)
	require.Error(t, err)
}

// === GetCaptcha ===

func TestGetCaptcha_Happy(t *testing.T) {
	svc := &mockAuthSvc{}
	cap := &mockCaptcha{
		genRes: policy.CaptchaChallenge{ID: "c-1", Image: []byte{0x89, 'P', 'N', 'G'}},
	}
	h, err := New(svc, cap)
	require.NoError(t, err)

	req := connect.NewRequest(&identityv1.GetCaptchaRequest{})
	res, err := h.GetCaptcha(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "c-1", res.Msg.GetCaptchaId())
	assert.NotEmpty(t, res.Msg.GetImagePng())
}

func TestGetCaptcha_Disabled(t *testing.T) {
	svc := &mockAuthSvc{}
	h, err := New(svc, nil) // captcha=nil
	require.NoError(t, err)

	req := connect.NewRequest(&identityv1.GetCaptchaRequest{})
	_, err = h.GetCaptcha(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

// === Login ===

func TestLogin_Happy(t *testing.T) {
	now := time.Now().UTC()
	svc := &mockAuthSvc{
		loginRes: &auth.LoginResult{
			AccessToken: "jwt-token-here",
			ExpiresAt:   now.Add(time.Hour),
			User: &domain.User{
				ID: "u-1", Username: "alice", TenantID: "t-1",
				Role: domain.RoleProjectAdmin, Status: domain.StatusActive,
				CreatedAt: now,
			},
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LoginRequest{
		Username: "alice", Password: "secret",
	})
	req.Header().Set("X-Forwarded-For", "203.0.113.1")
	req.Header().Set("User-Agent", "go-test/1.0")

	res, err := h.Login(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "jwt-token-here", res.Msg.GetAccessToken())
	assert.NotNil(t, res.Msg.GetUser())
	assert.Equal(t, "alice", res.Msg.GetUser().GetUsername())

	// header → service 注入正确
	assert.Equal(t, "alice", svc.loginReq.Username)
	assert.Equal(t, "203.0.113.1", svc.loginReq.ClientIP.String())
	assert.Equal(t, "go-test/1.0", svc.loginReq.UserAgent)
}

func TestLogin_PassesCaptchaFields(t *testing.T) {
	now := time.Now().UTC()
	svc := &mockAuthSvc{
		loginRes: &auth.LoginResult{
			AccessToken: "x",
			ExpiresAt:   now.Add(time.Hour),
			User: &domain.User{
				ID: "u-1", Username: "a", Role: domain.RoleProjectAdmin,
				Status: domain.StatusActive, CreatedAt: now,
			},
		},
	}
	h, _ := New(svc, nil)

	cid := "c-1"
	cans := "1234"
	req := connect.NewRequest(&identityv1.LoginRequest{
		Username:      "a",
		Password:      "p",
		CaptchaId:     &cid,
		CaptchaAnswer: &cans,
	})
	_, err := h.Login(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "c-1", svc.loginReq.CaptchaID)
	assert.Equal(t, "1234", svc.loginReq.CaptchaAnswer)
}

func TestLogin_FailedAuth(t *testing.T) {
	svc := &mockAuthSvc{
		loginErr: errx.New(errx.ErrAuthFailed, "用户名或密码错误"),
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LoginRequest{Username: "x", Password: "y"})
	_, err := h.Login(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestLogin_CaptchaRequired(t *testing.T) {
	svc := &mockAuthSvc{
		loginErr: errx.New(errx.ErrAuthCaptchaRequired, "请完成验证码"),
	}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.LoginRequest{Username: "x", Password: "y"})
	_, err := h.Login(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// === Logout ===

func TestLogout_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LogoutRequest{})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.Logout(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 1, svc.logoutCalls)
	assert.Equal(t, "sess-1", svc.logoutSession)
}

func TestLogout_NoAuth(t *testing.T) {
	svc := &mockAuthSvc{}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LogoutRequest{})
	_, err := h.Logout(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestLogout_BadHeaderFormat(t *testing.T) {
	svc := &mockAuthSvc{}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LogoutRequest{})
	req.Header().Set("Authorization", "Basic abc") // 非 Bearer
	_, err := h.Logout(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestLogout_APIKeyPrincipal_Rejected(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: &auth.UserPrincipal{
			UserID: "u-1", APIKeyID: "k-1", Source: auth.PrincipalSourceAPIKey,
			// SessionID 为空
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LogoutRequest{})
	for k, v := range bearerHeader("rmk_xxx") {
		req.Header()[k] = v
	}
	_, err := h.Logout(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

// === LogoutAllSessions ===

func TestLogoutAllSessions_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.LogoutAllSessionsRequest{})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.LogoutAllSessions(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 1, svc.logoutAllCalls)
	assert.Equal(t, "u-1", svc.logoutAllUser)
}

// === ListAPIKeys ===

func TestListAPIKeys_Happy(t *testing.T) {
	now := time.Now().UTC()
	rev := now.Add(-time.Minute)
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		listRes: []*domain.APIKey{
			{ID: "k1", UserID: "u-1", TenantID: "t-1", Name: "ci",
				KeyPrefix: "AB23CDEF", Scopes: []string{"scan:read"}, CreatedAt: now},
			{ID: "k2", UserID: "u-1", TenantID: "t-1", Name: "old",
				KeyPrefix: "ZZZZ2345", CreatedAt: now.Add(-time.Hour),
				RevokedAt: &rev},
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ListAPIKeysRequest{})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	res, err := h.ListAPIKeys(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Msg.GetKeys(), 2)
	assert.Equal(t, "k1", res.Msg.GetKeys()[0].GetId())
	assert.Equal(t, []string{"scan:read"}, res.Msg.GetKeys()[0].GetScopes())
	assert.NotNil(t, res.Msg.GetKeys()[1].GetRevokedAt(), "已撤销 key 应带 revoked_at")
}

// === CreateAPIKey ===

func TestCreateAPIKey_Happy(t *testing.T) {
	now := time.Now().UTC()
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		createRes: &auth.CreateAPIKeyResult{
			Plaintext: "rmk_AB23CDEF" + "abcdefghij1234567890ABCDEFGHIJ1234567890",
			Key: &domain.APIKey{
				ID: "k1", UserID: "u-1", TenantID: "t-1", Name: "ci",
				KeyPrefix: "AB23CDEF", CreatedAt: now,
			},
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.CreateAPIKeyRequest{
		Name:   "ci",
		Scopes: []string{"scan:read"},
	})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}

	res, err := h.CreateAPIKey(context.Background(), req)
	require.NoError(t, err)
	assert.NotEmpty(t, res.Msg.GetSecret())
	require.NotNil(t, res.Msg.GetKey())
	assert.Equal(t, "AB23CDEF", res.Msg.GetKey().GetKeyPrefix())

	// service 收到的 req owner 来自 principal
	assert.Equal(t, "u-1", svc.createReq.UserID)
	assert.Equal(t, "ci", svc.createReq.Name)
	assert.Equal(t, []string{"scan:read"}, svc.createReq.Scopes)
}

func TestCreateAPIKey_Disabled(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		createErr:     errx.New(errx.ErrNotImplemented, "API Key 功能未启用"),
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.CreateAPIKeyRequest{Name: "x"})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.CreateAPIKey(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnimplemented, connect.CodeOf(err))
}

// === RevokeAPIKey ===

func TestRevokeAPIKey_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.RevokeAPIKeyRequest{Id: "k1"})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.RevokeAPIKey(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "u-1", svc.revokeUser)
	assert.Equal(t, "k1", svc.revokeKey)
}

func TestRevokeAPIKey_NotFoundOnOwnerMismatch(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		revokeErr:     errx.New(errx.ErrAPIKeyNotFound, "api_key 不存在"),
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.RevokeAPIKeyRequest{Id: "k-other"})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.RevokeAPIKey(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
}

// === toConnectError ===

func TestToConnectError_Mapping(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want connect.Code
	}{
		{"nil", nil, connect.Code(0)},
		{"AUTH_FAILED", errx.New(errx.ErrAuthFailed, ""), connect.CodeUnauthenticated},
		{"INVALID_INPUT", errx.New(errx.ErrInvalidInput, ""), connect.CodeInvalidArgument},
		{"NOT_FOUND", errx.New(errx.ErrAPIKeyNotFound, ""), connect.CodeNotFound},
		{"NOT_IMPL", errx.New(errx.ErrNotImplemented, ""), connect.CodeUnimplemented},
		{"plain error → Internal", errors.New("boom"), connect.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toConnectError(tc.err)
			if tc.err == nil {
				assert.Nil(t, got)
				return
			}
			assert.Equal(t, tc.want, connect.CodeOf(got))
		})
	}
}

// === clientIP ===

func TestClientIP_XForwardedFor(t *testing.T) {
	h := http.Header{}
	h.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.5")
	a := clientIP(h)
	assert.Equal(t, "203.0.113.1", a.String())
}

func TestClientIP_XRealIP(t *testing.T) {
	h := http.Header{}
	h.Set("X-Real-IP", "203.0.113.42")
	a := clientIP(h)
	assert.Equal(t, "203.0.113.42", a.String())
}

func TestClientIP_None(t *testing.T) {
	a := clientIP(http.Header{})
	assert.False(t, a.IsValid())
}

// === GetCurrentUser ===

func TestGetCurrentUser_Happy(t *testing.T) {
	now := time.Now().UTC()
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		getCurrentRes: &domain.User{
			ID: "u-1", TenantID: "t-1", Username: "alice",
			Role: domain.RoleProjectAdmin, Status: domain.StatusActive,
			CreatedAt: now,
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.GetCurrentUserRequest{})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	res, err := h.GetCurrentUser(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, res.Msg.GetUser())
	assert.Equal(t, "alice", res.Msg.GetUser().GetUsername())
	assert.Equal(t, "u-1", svc.getCurrentUser, "应传 principal.UserID")
}

func TestGetCurrentUser_NoAuth(t *testing.T) {
	svc := &mockAuthSvc{}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.GetCurrentUserRequest{})
	_, err := h.GetCurrentUser(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// === ChangePassword ===

func TestChangePassword_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ChangePasswordRequest{
		CurrentPassword: "old-pwd",
		NewPassword:     "NewStrongPwd123!",
	})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	res, err := h.ChangePassword(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, res.Msg.GetAllSessionsRevoked())

	assert.Equal(t, "u-1", svc.changePwdUser, "应传 principal.UserID")
	assert.Equal(t, "old-pwd", svc.changePwdCurrent)
	assert.Equal(t, "NewStrongPwd123!", svc.changePwdNew)
}

func TestChangePassword_RejectsAPIKeyPrincipal(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: &auth.UserPrincipal{
			UserID: "u-1", APIKeyID: "k-1", Source: auth.PrincipalSourceAPIKey,
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ChangePasswordRequest{
		CurrentPassword: "x", NewPassword: "NewStrongPwd123!",
	})
	for k, v := range bearerHeader("rmk_xxx") {
		req.Header()[k] = v
	}
	_, err := h.ChangePassword(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestChangePassword_TooWeakBubbles(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		changePwdErr:  errx.New(errx.ErrAuthPasswordTooWeak, "新密码至少 12 字符"),
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ChangePasswordRequest{
		CurrentPassword: "old", NewPassword: "short",
	})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.ChangePassword(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
}

func TestChangePassword_WrongCurrentBubbles(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: authedPrincipal(),
		changePwdErr:  errx.New(errx.ErrAuthFailed, "当前密码错误"),
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ChangePasswordRequest{
		CurrentPassword: "wrong", NewPassword: "NewStrongPwd123!",
	})
	for k, v := range bearerHeader("jwt") {
		req.Header()[k] = v
	}
	_, err := h.ChangePassword(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

func TestChangePassword_NoAuth(t *testing.T) {
	svc := &mockAuthSvc{}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.ChangePasswordRequest{
		CurrentPassword: "x", NewPassword: "y",
	})
	_, err := h.ChangePassword(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// === User CRUD ===

// withSAAuth 给 req 设 Bearer header（同 fake JWT；mock 直接返 SA principal）
func withSAAuth(req interface{ Header() http.Header }) {
	req.Header().Set("Authorization", "Bearer fake-jwt")
}

// === CreateUser ===

func TestCreateUser_Happy_AsSA(t *testing.T) {
	now := time.Now().UTC()
	svc := &mockAuthSvc{
		authBearerRes: superAdminPrincipal(),
		createUserRes: &auth.CreateUserResult{
			TemporaryPassword: "TempPwd123!@#$%^",
			User: &domain.User{
				ID: "u-new", Username: "newbie",
				Role: domain.RoleProjectAdmin, Status: domain.StatusActive,
				TenantID: "t-1", CreatedAt: now,
			},
		},
	}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.CreateUserRequest{
		Username: "newbie", Email: "newbie@example.com",
		Role: "PROJECT_ADMIN", TenantId: "t-1",
	})
	withSAAuth(req)

	res, err := h.CreateUser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "TempPwd123!@#$%^", res.Msg.GetTemporaryPassword())
	require.NotNil(t, res.Msg.GetUser())
	assert.Equal(t, "newbie", res.Msg.GetUser().GetUsername())

	// service 收到正确入参
	assert.Equal(t, "newbie", svc.createUserReq.Username)
	assert.Equal(t, domain.RoleProjectAdmin, svc.createUserReq.Role)
	assert.Equal(t, "t-1", svc.createUserReq.TenantID)
}

func TestCreateUser_NonSA_Forbidden(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()} // ProjectAdmin
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.CreateUserRequest{
		Username: "x", Email: "x@example.com", Role: "PROJECT_ADMIN",
	})
	withSAAuth(req)

	_, err := h.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

func TestCreateUser_NoAuth(t *testing.T) {
	svc := &mockAuthSvc{}
	h, _ := New(svc, nil)

	req := connect.NewRequest(&identityv1.CreateUserRequest{Username: "x"})
	_, err := h.CreateUser(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodeUnauthenticated, connect.CodeOf(err))
}

// === ListUsers ===

func TestListUsers_AsSAOrAuditor(t *testing.T) {
	for _, p := range []*auth.UserPrincipal{superAdminPrincipal(), auditorPrincipal()} {
		svc := &mockAuthSvc{
			authBearerRes: p,
			listUsersRes: &auth.ListUsersResult{
				Users:    []*domain.User{{ID: "u-1", Username: "alice", Role: domain.RoleProjectAdmin}},
				Total:    1,
				Page:     1,
				PageSize: 20,
			},
		}
		h, _ := New(svc, nil)

		req := connect.NewRequest(&identityv1.ListUsersRequest{Page: 1, PageSize: 20})
		withSAAuth(req)
		res, err := h.ListUsers(context.Background(), req)
		require.NoError(t, err, "role=%s 应可读", p.Role)
		assert.Equal(t, int32(1), res.Msg.GetTotal())
	}
}

func TestListUsers_PA_Forbidden(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.ListUsersRequest{})
	withSAAuth(req)
	_, err := h.ListUsers(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// === GetUser ===

func TestGetUser_Happy(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: superAdminPrincipal(),
		getUserRes: &domain.User{
			ID: "u-x", Username: "x", Role: domain.RoleProjectAdmin,
			Status: domain.StatusActive, CreatedAt: time.Now(),
		},
	}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.GetUserRequest{Id: "u-x"})
	withSAAuth(req)
	res, err := h.GetUser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "u-x", res.Msg.GetUser().GetId())
	assert.Equal(t, "u-x", svc.getUserID)
}

// === EnableUser / DisableUser ===

func TestEnableUser_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: superAdminPrincipal()}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.EnableUserRequest{Id: "u-x"})
	withSAAuth(req)
	_, err := h.EnableUser(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "u-x", svc.enableID)
}

func TestDisableUser_NonSA_Forbidden(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: authedPrincipal()}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.DisableUserRequest{Id: "u-x"})
	withSAAuth(req)
	_, err := h.DisableUser(context.Background(), req)
	require.Error(t, err)
	assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
}

// === ResetPassword ===

func TestResetPassword_ReturnsTempPlaintext(t *testing.T) {
	svc := &mockAuthSvc{
		authBearerRes: superAdminPrincipal(),
		resetPwdRes:   "ResetTempPwd1!XY",
	}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.ResetPasswordRequest{Id: "u-x"})
	withSAAuth(req)
	res, err := h.ResetPassword(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "ResetTempPwd1!XY", res.Msg.GetTemporaryPassword())
}

// === ForceLogout ===

func TestForceLogout_Happy(t *testing.T) {
	svc := &mockAuthSvc{authBearerRes: superAdminPrincipal()}
	h, _ := New(svc, nil)
	req := connect.NewRequest(&identityv1.ForceLogoutRequest{Id: "u-x"})
	withSAAuth(req)
	_, err := h.ForceLogout(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "u-x", svc.forceLogoutID)
}

// === RequireRole 单测 ===

func TestRequireRole(t *testing.T) {
	cases := []struct {
		name    string
		p       *auth.UserPrincipal
		allowed []domain.Role
		ok      bool
	}{
		{"nil principal", nil, nil, false},
		{"empty allowed → 任何登录通过", &auth.UserPrincipal{Role: domain.RoleProjectAdmin}, nil, true},
		{"角色匹配", &auth.UserPrincipal{Role: domain.RoleSuperAdmin}, []domain.Role{domain.RoleSuperAdmin}, true},
		{"角色不匹配", &auth.UserPrincipal{Role: domain.RoleProjectAdmin}, []domain.Role{domain.RoleSuperAdmin}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := RequireRole(tc.p, tc.allowed...)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
