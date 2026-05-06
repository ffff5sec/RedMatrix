package auth

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/crypto"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
)

// === mocks ===

type mockUserRepo struct {
	users        map[string]*domain.User // by id
	byUsername   map[string]string       // username → id
	getByIDErr   error                   // 注入：GetByID 强制返错
	getByUserErr error
	logoutAllErr error
	logoutAllOK  int // 调用次数
	updateLogins int
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: map[string]*domain.User{}, byUsername: map[string]string{}}
}

func (m *mockUserRepo) put(u *domain.User) {
	if u.ID == "" {
		u.ID = "u-" + u.Username
	}
	m.users[u.ID] = u
	m.byUsername[u.Username] = u.ID
}

func (m *mockUserRepo) Create(_ context.Context, _ *domain.User) error { return errors.New("not impl") }

func (m *mockUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	u, ok := m.users[id]
	if !ok {
		return nil, errx.New(errx.ErrUserNotFound, "not found")
	}
	return u, nil
}

func (m *mockUserRepo) GetByUsername(_ context.Context, username string) (*domain.User, error) {
	if m.getByUserErr != nil {
		return nil, m.getByUserErr
	}
	id, ok := m.byUsername[username]
	if !ok {
		return nil, errx.New(errx.ErrUserNotFound, "not found")
	}
	return m.users[id], nil
}

func (m *mockUserRepo) UpdatePassword(_ context.Context, _, _ string, _ bool) error {
	return nil
}

func (m *mockUserRepo) UpdateLastLogin(_ context.Context, id string) error {
	if _, ok := m.users[id]; !ok {
		return errx.New(errx.ErrUserNotFound, "not found")
	}
	m.users[id].LastLoginAt = time.Now().UTC()
	m.updateLogins++
	return nil
}

func (m *mockUserRepo) IncrementTokenVersion(_ context.Context, id string) error {
	if u, ok := m.users[id]; ok {
		u.TokenVersion++
		return nil
	}
	return errx.New(errx.ErrUserNotFound, "not found")
}

func (m *mockUserRepo) UpdateStatus(_ context.Context, _ string, _ domain.Status) error { return nil }

func (m *mockUserRepo) LogoutAllSessions(_ context.Context, id string) error {
	if m.logoutAllErr != nil {
		return m.logoutAllErr
	}
	if u, ok := m.users[id]; ok {
		u.TokenVersion++
		m.logoutAllOK++
		return nil
	}
	return errx.New(errx.ErrUserNotFound, "not found")
}

type mockSessionRepo struct {
	rows           map[string]*domain.Session
	createErr      error
	deleteErr      error
	createCalls    int
	deleteCalls    int
	expireAllCalls int
	lastSeenCalls  int
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{rows: map[string]*domain.Session{}}
}

func (m *mockSessionRepo) Create(_ context.Context, s *domain.Session) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	if s.ID == "" {
		s.ID = "sess-" + s.UserID
	}
	if err := s.ValidateForCreate(); err != nil {
		return err
	}
	m.rows[s.ID] = s
	return nil
}

func (m *mockSessionRepo) GetByID(_ context.Context, id string) (*domain.Session, error) {
	s, ok := m.rows[id]
	if !ok {
		return nil, errx.New(errx.ErrSessionNotFound, "not found")
	}
	return s, nil
}

func (m *mockSessionRepo) ListByUser(_ context.Context, userID string) ([]*domain.Session, error) {
	var out []*domain.Session
	for _, s := range m.rows {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *mockSessionRepo) Delete(_ context.Context, id string) error {
	m.deleteCalls++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.rows[id]; !ok {
		return errx.New(errx.ErrSessionNotFound, "not found")
	}
	delete(m.rows, id)
	return nil
}

func (m *mockSessionRepo) ExpireAllByUser(_ context.Context, userID string) error {
	m.expireAllCalls++
	now := time.Now().UTC()
	for _, s := range m.rows {
		if s.UserID == userID {
			s.ExpiresAt = now
		}
	}
	return nil
}

func (m *mockSessionRepo) UpdateLastSeen(_ context.Context, id string) error {
	m.lastSeenCalls++
	if s, ok := m.rows[id]; ok {
		s.LastSeenAt = time.Now().UTC()
		return nil
	}
	return errx.New(errx.ErrSessionNotFound, "not found")
}

type mockLockout struct {
	ipLocked         bool
	ipLockedUntil    time.Time
	acctLocked       bool
	acctLockedUntil  time.Time
	recordCalls      int
	resetCalls       int
	lastFailureUser  string
	lastFailureIP    string
	nextRecordResult [2]bool // 注入：下次 RecordFailure 返回值
}

func (m *mockLockout) IsIPLocked(_ context.Context, _ netip.Addr) (bool, time.Time) {
	return m.ipLocked, m.ipLockedUntil
}

func (m *mockLockout) IsAccountLocked(_ context.Context, _ string) (bool, time.Time) {
	return m.acctLocked, m.acctLockedUntil
}

func (m *mockLockout) RecordFailure(_ context.Context, ip netip.Addr, userID string) (bool, bool) {
	m.recordCalls++
	m.lastFailureUser = userID
	m.lastFailureIP = ip.String()
	return m.nextRecordResult[0], m.nextRecordResult[1]
}

func (m *mockLockout) ResetFailures(_ context.Context, _ netip.Addr, _ string) {
	m.resetCalls++
}

// mockCaptcha 让 AuthService 单测可控制 IsRequired/Verify 返回。
type mockCaptcha struct {
	required     bool
	verifyOK     bool
	verifyErr    error
	verifyCalls  int
	requireCalls int
}

func (m *mockCaptcha) Generate(_ context.Context) (policy.CaptchaChallenge, error) {
	return policy.CaptchaChallenge{ID: "c-1", Image: []byte{0x89, 'P', 'N', 'G'}}, nil
}

func (m *mockCaptcha) Verify(_ context.Context, _, _ string) (bool, error) {
	m.verifyCalls++
	return m.verifyOK, m.verifyErr
}

func (m *mockCaptcha) IsRequired(_ context.Context, _ netip.Addr, _ string) bool {
	m.requireCalls++
	return m.required
}

// === fixtures ===

const (
	testJWTSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64
	knownPlain    = "Pa$$w0rd1234"
)

func setupSvc(t *testing.T) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, jwt, nil, nil) // lockout=nil + captcha=nil
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func setupSvcWithLockout(t *testing.T, l *mockLockout) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, jwt, l, nil)
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func setupSvcWithCaptcha(t *testing.T, c *mockCaptcha) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, jwt, nil, c)
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func mustHash(t *testing.T, plain string) string {
	t.Helper()
	h, err := domain.HashPassword(plain)
	require.NoError(t, err)
	return h
}

func newActiveUser(t *testing.T, username string) *domain.User {
	t.Helper()
	return &domain.User{
		ID:           "u-" + username,
		TenantID:     "11111111-1111-1111-1111-111111111111",
		Username:     username,
		PasswordHash: mustHash(t, knownPlain),
		Role:         domain.RoleProjectAdmin,
		Status:       domain.StatusActive,
		TokenVersion: 0,
	}
}

// === New ===

func TestNew_RejectsNilDeps(t *testing.T) {
	jwt, _ := crypto.NewService(testJWTSecret, time.Hour)
	_, err := New(nil, nil, jwt, nil, nil)
	require.Error(t, err)
}

func TestNew_AcceptsNilLockoutAndCaptcha(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, _ := crypto.NewService(testJWTSecret, time.Hour)
	_, err := New(users, sessions, jwt, nil, nil)
	require.NoError(t, err, "lockout 与 captcha 均可空（dev / 单测）")
}

// === Login ===

func TestLogin_Success(t *testing.T) {
	svc, users, sessions, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	res, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain, UserAgent: "go-test",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.NotEmpty(t, res.AccessToken)
	assert.False(t, res.ExpiresAt.IsZero())
	assert.Equal(t, u.ID, res.User.ID)
	assert.NotEmpty(t, res.SessionID)
	assert.False(t, res.MustChangePassword)

	// 必须写了一条 session 行
	assert.Equal(t, 1, sessions.createCalls)

	// last_login_at 必须刷过
	assert.Equal(t, 1, users.updateLogins)
}

func TestLogin_BadPassword(t *testing.T) {
	svc, _, sessions, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	svc.users.(*mockUserRepo).put(u)

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: "wrong",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c)
	assert.Equal(t, 0, sessions.createCalls, "失败时不应写 session")
}

func TestLogin_UnknownUser_StillRunsDummyVerify(t *testing.T) {
	svc, _, sessions, _ := setupSvc(t)

	start := time.Now()
	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "ghost", Password: "anything",
	})
	elapsed := time.Since(start)

	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "未知用户混淆为 AUTH_FAILED")
	assert.Equal(t, 0, sessions.createCalls)
	// 防枚举：dummy verify 必须真跑过 argon2id（>= 5ms 经验下限；不同机器跨度大）
	assert.GreaterOrEqual(t, elapsed, 5*time.Millisecond,
		"未知用户也必须跑 argon2id 验证")
}

func TestLogin_DisabledUser(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "bob")
	u.Status = domain.StatusDisabled
	users.put(u)

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "bob", Password: knownPlain,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "disabled 用户混淆为 AUTH_FAILED")
}

func TestLogin_EmptyInputs(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	for _, tc := range []LoginRequest{
		{Username: "", Password: knownPlain},
		{Username: "alice", Password: ""},
		{Username: "  ", Password: knownPlain},
	} {
		_, err := svc.Login(context.Background(), tc)
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrAuthFailed, c)
	}
}

func TestLogin_DBFailureBubblesUp(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.getByUserErr = errx.New(errx.ErrDatabase, "boom")

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

func TestLogin_SetsMustChangeFlag(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	u.MustChangePassword = true
	users.put(u)

	res, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
	})
	require.NoError(t, err)
	assert.True(t, res.MustChangePassword)
}

// JWT.Issue 在 HS256 + 内存签名下几乎不可能失败；rollback 是 best-effort 兜底
// （也无法用单元测试可靠触发）。保留代码路径不写测试 — 价值低且抖动大。

// === Login + Lockout ===

func TestLogin_IPLocked_RejectsEarly(t *testing.T) {
	lock := &mockLockout{
		ipLocked:      true,
		ipLockedUntil: time.Now().Add(10 * time.Minute),
	}
	svc, users, sessions, _ := setupSvcWithLockout(t, lock)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		ClientIP: netip.MustParseAddr("203.0.113.1"),
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthIPLocked, c)
	assert.Equal(t, 0, sessions.createCalls, "IP 锁定应早退；不写 session")
	assert.Equal(t, 0, lock.recordCalls, "IP 锁定不应再计失败")
}

func TestLogin_AccountLocked_AfterPasswordOK(t *testing.T) {
	lock := &mockLockout{
		acctLocked:      true,
		acctLockedUntil: time.Now().Add(15 * time.Minute),
	}
	svc, users, sessions, _ := setupSvcWithLockout(t, lock)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		ClientIP: netip.MustParseAddr("203.0.113.2"),
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthAccountLocked, c, "密码对+账号锁定 → AUTH_ACCOUNT_LOCKED")
	assert.Equal(t, 0, sessions.createCalls)
	assert.Equal(t, 0, lock.recordCalls, "账号已锁定不应再计失败")
}

func TestLogin_AccountLockedButPasswordWrong_StillAuthFailed(t *testing.T) {
	// 即便账号已锁定，密码错误时仍混淆为 AUTH_FAILED（不暴露账号状态）
	lock := &mockLockout{
		acctLocked:      true,
		acctLockedUntil: time.Now().Add(15 * time.Minute),
	}
	svc, users, _, _ := setupSvcWithLockout(t, lock)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: "wrong",
		ClientIP: netip.MustParseAddr("203.0.113.3"),
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c)
	assert.Equal(t, 1, lock.recordCalls, "密码错走失败计数（即便账号锁定）")
}

func TestLogin_RecordsFailureOnBadPassword(t *testing.T) {
	lock := &mockLockout{}
	svc, users, _, _ := setupSvcWithLockout(t, lock)
	u := newActiveUser(t, "alice")
	users.put(u)

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: "wrong",
		ClientIP: netip.MustParseAddr("203.0.113.4"),
	})
	require.Error(t, err)
	assert.Equal(t, 1, lock.recordCalls)
	assert.Equal(t, u.ID, lock.lastFailureUser, "找到的 user 应记入账号维度")
	assert.Equal(t, "203.0.113.4", lock.lastFailureIP)
}

func TestLogin_RecordsFailureOnUnknownUser_OnlyIP(t *testing.T) {
	lock := &mockLockout{}
	svc, _, _, _ := setupSvcWithLockout(t, lock)

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "ghost", Password: "anything",
		ClientIP: netip.MustParseAddr("203.0.113.5"),
	})
	require.Error(t, err)
	assert.Equal(t, 1, lock.recordCalls)
	assert.Equal(t, "", lock.lastFailureUser, "用户不存在时 userID 空，仅 IP 维度计")
	assert.Equal(t, "203.0.113.5", lock.lastFailureIP)
}

func TestLogin_ResetsFailuresOnSuccess(t *testing.T) {
	lock := &mockLockout{}
	svc, users, _, _ := setupSvcWithLockout(t, lock)
	users.put(newActiveUser(t, "alice"))

	res, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		ClientIP: netip.MustParseAddr("203.0.113.6"),
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, lock.resetCalls)
	assert.Equal(t, 0, lock.recordCalls)
}

func TestLogin_DBError_DoesNotCountFailure(t *testing.T) {
	lock := &mockLockout{}
	svc, users, _, _ := setupSvcWithLockout(t, lock)
	users.getByUserErr = errx.New(errx.ErrDatabase, "boom")

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		ClientIP: netip.MustParseAddr("203.0.113.7"),
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
	assert.Equal(t, 0, lock.recordCalls, "DB 故障不应当作登录失败计")
}

// === Login + Captcha ===

func TestLogin_CaptchaNotRequired_NoVerifyCalled(t *testing.T) {
	cap := &mockCaptcha{required: false}
	svc, users, _, _ := setupSvcWithCaptcha(t, cap)
	users.put(newActiveUser(t, "alice"))

	res, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, cap.requireCalls)
	assert.Equal(t, 0, cap.verifyCalls, "IsRequired=false → 不应调 Verify")
}

func TestLogin_CaptchaRequired_MissingFields(t *testing.T) {
	cap := &mockCaptcha{required: true}
	svc, users, sessions, _ := setupSvcWithCaptcha(t, cap)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		// 不填 CaptchaID / CaptchaAnswer
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthCaptchaRequired, c)
	assert.Equal(t, 0, cap.verifyCalls, "缺字段不应调 Verify")
	assert.Equal(t, 0, sessions.createCalls)
}

func TestLogin_CaptchaRequired_WrongAnswer(t *testing.T) {
	cap := &mockCaptcha{required: true, verifyOK: false}
	svc, users, sessions, _ := setupSvcWithCaptcha(t, cap)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		CaptchaID: "c-1", CaptchaAnswer: "wrong",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthCaptchaInvalid, c)
	assert.Equal(t, 1, cap.verifyCalls)
	assert.Equal(t, 0, sessions.createCalls)
}

func TestLogin_CaptchaRequired_Correct_ContinuesToPasswordCheck(t *testing.T) {
	cap := &mockCaptcha{required: true, verifyOK: true}
	svc, users, sessions, _ := setupSvcWithCaptcha(t, cap)
	users.put(newActiveUser(t, "alice"))

	res, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		CaptchaID: "c-1", CaptchaAnswer: "right",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, cap.verifyCalls)
	assert.Equal(t, 1, sessions.createCalls)
}

func TestLogin_CaptchaRedisFailure_BubblesUp(t *testing.T) {
	cap := &mockCaptcha{
		required:  true,
		verifyErr: errx.New(errx.ErrInternal, "redis down"),
	}
	svc, users, sessions, _ := setupSvcWithCaptcha(t, cap)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.Login(context.Background(), LoginRequest{
		Username: "alice", Password: knownPlain,
		CaptchaID: "c-1", CaptchaAnswer: "abc",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c, "Redis 故障透传 internal（不是 INVALID）")
	assert.Equal(t, 0, sessions.createCalls)
}

// === AuthenticateBearer ===

func TestAuthenticateBearer_JWTHappyPath(t *testing.T) {
	svc, users, _, jwt := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	raw, _, err := jwt.Issue(u, "sess-1")
	require.NoError(t, err)

	p, err := svc.AuthenticateBearer(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, u.ID, p.UserID)
	assert.Equal(t, u.TenantID, p.TenantID)
	assert.Equal(t, u.Username, p.Username)
	assert.Equal(t, u.Role, p.Role)
	assert.Equal(t, u.TokenVersion, p.TokenVersion)
	assert.Equal(t, "sess-1", p.SessionID)
	assert.Equal(t, PrincipalSourceJWT, p.Source)
}

func TestAuthenticateBearer_TVMismatch(t *testing.T) {
	svc, users, _, jwt := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	raw, _, _ := jwt.Issue(u, "sess-1")

	// 改密 / 强制下线 后 tv++
	require.NoError(t, users.IncrementTokenVersion(context.Background(), u.ID))

	_, err := svc.AuthenticateBearer(context.Background(), raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenVersionMismatch, c)
}

func TestAuthenticateBearer_DisabledUser(t *testing.T) {
	svc, users, _, jwt := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	raw, _, _ := jwt.Issue(u, "sess-1")
	u.Status = domain.StatusDisabled

	_, err := svc.AuthenticateBearer(context.Background(), raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c)
}

func TestAuthenticateBearer_UserGone(t *testing.T) {
	svc, users, _, jwt := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	raw, _, _ := jwt.Issue(u, "sess-1")
	delete(users.users, u.ID)
	delete(users.byUsername, u.Username)

	_, err := svc.AuthenticateBearer(context.Background(), raw)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "用户被删后混淆为 AUTH_FAILED")
}

func TestAuthenticateBearer_GarbageJWT(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.AuthenticateBearer(context.Background(), "not.a.jwt")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestAuthenticateBearer_Empty(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.AuthenticateBearer(context.Background(), "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenInvalid, c)
}

func TestAuthenticateBearer_APIKeyPrefix_NotImplemented(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.AuthenticateBearer(context.Background(), "rmk_some_api_key_value")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNotImplemented, c)
}

// === Logout ===

func TestLogout_DeletesSession(t *testing.T) {
	svc, _, sessions, _ := setupSvc(t)
	now := time.Now().UTC()
	s := &domain.Session{
		ID: "sess-1", UserID: "u-1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now,
	}
	sessions.rows["sess-1"] = s

	require.NoError(t, svc.Logout(context.Background(), "sess-1"))
	assert.Equal(t, 1, sessions.deleteCalls)
	_, exists := sessions.rows["sess-1"]
	assert.False(t, exists)
}

func TestLogout_EmptySession(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	err := svc.Logout(context.Background(), "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestLogout_NotFound(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	err := svc.Logout(context.Background(), "nonexistent")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrSessionNotFound, c)
}

// === LogoutAllSessions ===

func TestLogoutAllSessions_BumpsTV(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	require.NoError(t, svc.LogoutAllSessions(context.Background(), u.ID))
	assert.Equal(t, 1, u.TokenVersion, "tv 应+1")
	assert.Equal(t, 1, users.logoutAllOK)
}

func TestLogoutAllSessions_EmptyID(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	err := svc.LogoutAllSessions(context.Background(), "")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestLogoutAllSessions_Repeated(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	for i := 0; i < 3; i++ {
		require.NoError(t, svc.LogoutAllSessions(context.Background(), u.ID))
	}
	assert.Equal(t, 3, u.TokenVersion)
}

func TestLogoutAllSessions_RepoError(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.logoutAllErr = errx.New(errx.ErrDatabase, "boom")

	err := svc.LogoutAllSessions(context.Background(), "u-1")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

// 静态断言 — 确认 mock 实现了接口。
var _ = func() bool {
	var _ = newMockUserRepo()
	return strings.HasPrefix(authAPIKeyPrefix, "rmk_")
}()
