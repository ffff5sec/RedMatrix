package auth

import (
	"context"
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
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
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

func (m *mockUserRepo) Create(_ context.Context, u *domain.User) error {
	if err := u.ValidateForCreate(); err != nil {
		return err
	}
	if u.ID == "" {
		u.ID = "u-" + u.Username
	}
	if _, dup := m.byUsername[u.Username]; dup {
		return errx.New(errx.ErrUserUsernameExists, "username 已存在")
	}
	m.users[u.ID] = u
	m.byUsername[u.Username] = u.ID
	return nil
}

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

func (m *mockUserRepo) UpdatePassword(_ context.Context, id, newHash string, mustChange bool) error {
	u, ok := m.users[id]
	if !ok {
		return errx.New(errx.ErrUserNotFound, "not found")
	}
	u.PasswordHash = newHash
	u.MustChangePassword = mustChange
	u.TokenVersion++ // 与 pg 行为对齐：UpdatePassword 自动 tv++
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

func (m *mockUserRepo) UpdateStatus(_ context.Context, id string, status domain.Status) error {
	if u, ok := m.users[id]; ok {
		u.Status = status
		return nil
	}
	return errx.New(errx.ErrUserNotFound, "not found")
}

func (m *mockUserRepo) CountByRole(_ context.Context, role domain.Role) (int, error) {
	n := 0
	for _, u := range m.users {
		if u.Role == role {
			n++
		}
	}
	return n, nil
}

func (m *mockUserRepo) List(_ context.Context, f repo.ListFilter, p repo.Page) ([]*domain.User, int, error) {
	var matched []*domain.User
	for _, u := range m.users {
		if f.Status != "" && u.Status != f.Status {
			continue
		}
		if f.Role != "" && u.Role != f.Role {
			continue
		}
		if f.Keyword != "" {
			kw := strings.ToLower(f.Keyword)
			if !strings.Contains(strings.ToLower(u.Username), kw) &&
				!strings.Contains(strings.ToLower(u.Email), kw) {
				continue
			}
		}
		matched = append(matched, u)
	}
	total := len(matched)
	if p.PageSize <= 0 {
		p.PageSize = 20
	}
	if p.Page < 1 {
		p.Page = 1
	}
	start := (p.Page - 1) * p.PageSize
	end := start + p.PageSize
	if start > total {
		return nil, total, nil
	}
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

func (m *mockUserRepo) UpdateEmail(_ context.Context, id, email string) error {
	if u, ok := m.users[id]; ok {
		u.Email = email
		return nil
	}
	return errx.New(errx.ErrUserNotFound, "not found")
}

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

// mockAPIKeyRepo 让 AuthService 单测可注入 keys repo 行为。
type mockAPIKeyRepo struct {
	rows               map[string]*domain.APIKey
	byPrefix           map[string]string // prefix → id
	insertErr          error
	findErr            error
	getErr             error
	revokeErr          error
	updateLastUsedErr  error
	insertCalls        int
	findCalls          int
	getCalls           int
	revokeCalls        int
	listCalls          int
	updateLastUseCalls int
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{
		rows:     map[string]*domain.APIKey{},
		byPrefix: map[string]string{},
	}
}

func (m *mockAPIKeyRepo) Insert(_ context.Context, k *domain.APIKey) error {
	m.insertCalls++
	if m.insertErr != nil {
		return m.insertErr
	}
	if err := k.ValidateForCreate(); err != nil {
		return err
	}
	if _, dup := m.byPrefix[k.KeyPrefix]; dup {
		return errx.New(errx.ErrDatabase, "prefix unique violation")
	}
	if k.ID == "" {
		k.ID = "k-" + k.KeyPrefix
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	m.rows[k.ID] = k
	m.byPrefix[k.KeyPrefix] = k.ID
	return nil
}

func (m *mockAPIKeyRepo) GetByID(_ context.Context, id string) (*domain.APIKey, error) {
	m.getCalls++
	if m.getErr != nil {
		return nil, m.getErr
	}
	k, ok := m.rows[id]
	if !ok {
		return nil, errx.New(errx.ErrAPIKeyNotFound, "not found")
	}
	return k, nil
}

func (m *mockAPIKeyRepo) FindByPrefix(_ context.Context, prefix string) (*domain.APIKey, error) {
	m.findCalls++
	if m.findErr != nil {
		return nil, m.findErr
	}
	id, ok := m.byPrefix[prefix]
	if !ok {
		return nil, errx.New(errx.ErrAPIKeyNotFound, "not found")
	}
	return m.rows[id], nil
}

func (m *mockAPIKeyRepo) ListByUser(_ context.Context, userID string) ([]*domain.APIKey, error) {
	m.listCalls++
	var out []*domain.APIKey
	for _, k := range m.rows {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *mockAPIKeyRepo) Revoke(_ context.Context, id string) error {
	m.revokeCalls++
	if m.revokeErr != nil {
		return m.revokeErr
	}
	k, ok := m.rows[id]
	if !ok {
		return errx.New(errx.ErrAPIKeyNotFound, "not found")
	}
	if k.RevokedAt == nil {
		now := time.Now().UTC()
		k.RevokedAt = &now
	}
	return nil
}

func (m *mockAPIKeyRepo) UpdateLastUsed(_ context.Context, id string) error {
	m.updateLastUseCalls++
	if m.updateLastUsedErr != nil {
		return m.updateLastUsedErr
	}
	if k, ok := m.rows[id]; ok {
		now := time.Now().UTC()
		k.LastUsedAt = &now
		return nil
	}
	return errx.New(errx.ErrAPIKeyNotFound, "not found")
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
	svc, err := New(users, sessions, nil, jwt, nil, nil) // keys/lockout/captcha = nil
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func setupSvcWithLockout(t *testing.T, l *mockLockout) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, nil, jwt, l, nil)
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func setupSvcWithCaptcha(t *testing.T, c *mockCaptcha) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, nil, jwt, nil, c)
	require.NoError(t, err)
	return svc.(*service), users, sessions, jwt
}

func setupSvcWithKeys(t *testing.T, k *mockAPIKeyRepo) (*service, *mockUserRepo, *mockSessionRepo, *crypto.Service) {
	t.Helper()
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, err := crypto.NewService(testJWTSecret, time.Hour)
	require.NoError(t, err)
	svc, err := New(users, sessions, k, jwt, nil, nil)
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
	_, err := New(nil, nil, nil, jwt, nil, nil)
	require.Error(t, err)
}

func TestNew_AcceptsOptionalDeps(t *testing.T) {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	jwt, _ := crypto.NewService(testJWTSecret, time.Hour)
	_, err := New(users, sessions, nil, jwt, nil, nil)
	require.NoError(t, err, "keys / lockout / captcha 均可空（dev / 单测）")
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

// keys nil 时 rmk_ 路径仍返 NOT_IMPLEMENTED（功能开关 OFF）
func TestAuthenticateBearer_APIKeyPrefix_NotImplementedWhenKeysNil(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.AuthenticateBearer(context.Background(),
		"rmk_AB23CDEF"+strings.Repeat("a", 40))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNotImplemented, c)
}

// === Login + JWT 已覆盖；下面是 API Key path / CRUD ===

// === AuthenticateBearer rmk_ 路径 ===

// 帮 fixture：插入一条可用的 key 并把 plaintext 也返回
func insertActiveKey(t *testing.T, svc *service, owner *domain.User, name string) string {
	t.Helper()
	res, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: owner.ID,
		Name:   name,
	})
	require.NoError(t, err)
	require.NotEmpty(t, res.Plaintext)
	return res.Plaintext
}

func TestAuthenticateBearer_APIKey_Happy(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)

	plaintext := insertActiveKey(t, svc, u, "ci-bot")

	p, err := svc.AuthenticateBearer(context.Background(), plaintext)
	require.NoError(t, err)
	assert.Equal(t, u.ID, p.UserID)
	assert.Equal(t, u.TenantID, p.TenantID)
	assert.Equal(t, u.Username, p.Username)
	assert.Equal(t, u.Role, p.Role)
	assert.Equal(t, PrincipalSourceAPIKey, p.Source)
	assert.NotEmpty(t, p.APIKeyID)
	assert.Empty(t, p.SessionID, "API Key 路径不应有 SessionID")
}

func TestAuthenticateBearer_APIKey_BadFormat(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, _, _, _ := setupSvcWithKeys(t, keys)

	cases := []struct {
		name string
		raw  string
	}{
		{"too short", "rmk_short"},
		{"short by one", "rmk_AB23CDEF" + strings.Repeat("a", 39)},
		{"prefix has 0", "rmk_0BCDEFGH" + strings.Repeat("a", 40)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			_, err := svc.AuthenticateBearer(context.Background(), raw)
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrAuthFailed, c, "解析错混淆为 AUTH_FAILED")
		})
	}
}

func TestAuthenticateBearer_APIKey_PrefixNotFound(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, _, _, _ := setupSvcWithKeys(t, keys)

	// 合法格式但 prefix 不存在
	_, err := svc.AuthenticateBearer(context.Background(),
		"rmk_GHOSTABC"+strings.Repeat("z", 40))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "prefix 不存在混淆为 AUTH_FAILED")
}

func TestAuthenticateBearer_APIKey_WrongSecret(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)
	plaintext := insertActiveKey(t, svc, u, "ci-bot")

	// 改尾部字符破坏 secret，但保留 prefix
	wrong := plaintext[:12] + strings.Repeat("X", 40)
	_, err := svc.AuthenticateBearer(context.Background(), wrong)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "secret 错混淆为 AUTH_FAILED")
}

func TestAuthenticateBearer_APIKey_Revoked(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)
	plaintext := insertActiveKey(t, svc, u, "revoke-test")

	// 直接修改 mock 中的 RevokedAt
	for _, k := range keys.rows {
		now := time.Now().UTC()
		k.RevokedAt = &now
	}

	_, err := svc.AuthenticateBearer(context.Background(), plaintext)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthAPIKeyRevoked, c)
}

func TestAuthenticateBearer_APIKey_Expired(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)
	plaintext := insertActiveKey(t, svc, u, "exp-test")

	for _, k := range keys.rows {
		past := time.Now().Add(-time.Hour)
		k.ExpiresAt = &past
	}

	_, err := svc.AuthenticateBearer(context.Background(), plaintext)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthTokenExpired, c)
}

func TestAuthenticateBearer_APIKey_UserDisabled(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)
	plaintext := insertActiveKey(t, svc, u, "user-disabled")

	u.Status = domain.StatusDisabled

	_, err := svc.AuthenticateBearer(context.Background(), plaintext)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "user 非 active 混淆为 AUTH_FAILED")
}

func TestAuthenticateBearer_APIKey_UserGone(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)
	plaintext := insertActiveKey(t, svc, u, "user-gone")

	delete(users.users, u.ID)
	delete(users.byUsername, u.Username)

	_, err := svc.AuthenticateBearer(context.Background(), plaintext)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c)
}

func TestAuthenticateBearer_APIKey_DBError(t *testing.T) {
	keys := newMockAPIKeyRepo()
	keys.findErr = errx.New(errx.ErrDatabase, "boom")
	svc, _, _, _ := setupSvcWithKeys(t, keys)

	_, err := svc.AuthenticateBearer(context.Background(),
		"rmk_AB23CDEF"+strings.Repeat("a", 40))
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c, "DB 错原样透")
}

// === CreateAPIKey ===

func TestCreateAPIKey_Happy(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)

	res, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: u.ID,
		Name:   "ci-bot",
		Scopes: []string{"scan:read"},
	})
	require.NoError(t, err)
	require.NotNil(t, res.Key)
	assert.NotEmpty(t, res.Plaintext)
	assert.True(t, strings.HasPrefix(res.Plaintext, "rmk_"))
	assert.Empty(t, res.Key.SecretHash, "返给 caller 的 Key 必须清空 SecretHash")
	assert.Equal(t, u.ID, res.Key.UserID)
	assert.Equal(t, u.TenantID, res.Key.TenantID)
	assert.Equal(t, "ci-bot", res.Key.Name)
	assert.Equal(t, []string{"scan:read"}, res.Key.Scopes)
	assert.Equal(t, 1, keys.insertCalls)
}

func TestCreateAPIKey_KeysNil_NotImplemented(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.put(newActiveUser(t, "alice"))

	_, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: "u-alice", Name: "x",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNotImplemented, c)
}

func TestCreateAPIKey_EmptyInputs(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	users.put(newActiveUser(t, "alice"))

	for _, tc := range []CreateAPIKeyRequest{
		{UserID: "", Name: "ci"},
		{UserID: "u-alice", Name: ""},
		{UserID: "u-alice", Name: "  "},
	} {
		_, err := svc.CreateAPIKey(context.Background(), tc)
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

func TestCreateAPIKey_UserNotFound(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, _, _, _ := setupSvcWithKeys(t, keys)

	_, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: "u-ghost", Name: "ci",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

func TestCreateAPIKey_DisabledUser(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	u.Status = domain.StatusDisabled
	users.put(u)

	_, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: u.ID, Name: "ci",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c, "disabled 用户禁创 key")
}

// === ListAPIKeys ===

func TestListAPIKeys_SanitizesSecretHash(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)

	for i := 0; i < 3; i++ {
		_, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
			UserID: u.ID, Name: "k" + string(rune('a'+i)),
		})
		require.NoError(t, err)
	}

	got, err := svc.ListAPIKeys(context.Background(), u.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	for _, k := range got {
		assert.Empty(t, k.SecretHash, "List 返回必须清空 SecretHash")
	}
}

func TestListAPIKeys_KeysNil(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.ListAPIKeys(context.Background(), "u-1")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNotImplemented, c)
}

// === RevokeAPIKey ===

func TestRevokeAPIKey_Happy(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	u := newActiveUser(t, "alice")
	users.put(u)

	res, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: u.ID, Name: "to-revoke",
	})
	require.NoError(t, err)

	require.NoError(t, svc.RevokeAPIKey(context.Background(), u.ID, res.Key.ID))
	assert.Equal(t, 1, keys.revokeCalls)

	// 后续 Bearer 应返 REVOKED
	_, err = svc.AuthenticateBearer(context.Background(), res.Plaintext)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthAPIKeyRevoked, c)
}

func TestRevokeAPIKey_OwnerMismatch(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	alice := newActiveUser(t, "alice")
	bob := newActiveUser(t, "bob")
	users.put(alice)
	users.put(bob)

	res, err := svc.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		UserID: alice.ID, Name: "alice-key",
	})
	require.NoError(t, err)

	// bob 试图撤 alice 的 key → 防 ID 枚举返 NotFound
	err = svc.RevokeAPIKey(context.Background(), bob.ID, res.Key.ID)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
	assert.Equal(t, 0, keys.revokeCalls, "owner mismatch 不应调 Revoke")
}

func TestRevokeAPIKey_NotFound(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, users, _, _ := setupSvcWithKeys(t, keys)
	users.put(newActiveUser(t, "alice"))

	err := svc.RevokeAPIKey(context.Background(), "u-alice", "k-ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAPIKeyNotFound, c)
}

func TestRevokeAPIKey_EmptyInputs(t *testing.T) {
	keys := newMockAPIKeyRepo()
	svc, _, _, _ := setupSvcWithKeys(t, keys)

	for _, tc := range [][2]string{{"", "k-1"}, {"u-1", ""}} {
		err := svc.RevokeAPIKey(context.Background(), tc[0], tc[1])
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

func TestRevokeAPIKey_KeysNil(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	err := svc.RevokeAPIKey(context.Background(), "u-1", "k-1")
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

// === GetCurrentUser ===

func TestGetCurrentUser_Happy(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	got, err := svc.GetCurrentUser(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, "alice", got.Username)
	assert.Empty(t, got.PasswordHash, "GetCurrentUser 必须清空 PasswordHash")
}

func TestGetCurrentUser_NotFound(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.GetCurrentUser(context.Background(), "u-ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c, "GetCurrentUser 透传 NotFound（caller 决定混淆）")
}

func TestGetCurrentUser_EmptyID(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.GetCurrentUser(context.Background(), "  ")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === ChangePassword ===

func TestChangePassword_Happy(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)
	originalHash := u.PasswordHash
	originalTV := u.TokenVersion

	const newPwd = "NewStrongPwd123!"
	err := svc.ChangePassword(context.Background(), u.ID, knownPlain, newPwd)
	require.NoError(t, err)

	// hash 已更换
	assert.NotEqual(t, originalHash, u.PasswordHash)
	// 新密码可校验
	ok, _ := domain.VerifyPassword(newPwd, u.PasswordHash)
	assert.True(t, ok)
	// tv 已 +1（让所有现存 JWT 失效）
	assert.Equal(t, originalTV+1, u.TokenVersion)
	// must_change_password 清掉
	assert.False(t, u.MustChangePassword)
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	originalHash := u.PasswordHash
	users.put(u)

	err := svc.ChangePassword(context.Background(), u.ID, "wrong-current", "NewStrongPwd123!")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c)
	assert.Equal(t, originalHash, u.PasswordHash, "失败不应改 hash")
}

func TestChangePassword_NewTooShort(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	err := svc.ChangePassword(context.Background(), u.ID, knownPlain, "shortpwd")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthPasswordTooWeak, c)
}

func TestChangePassword_SameAsCurrent(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	err := svc.ChangePassword(context.Background(), u.ID, knownPlain, knownPlain)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthPasswordReuse, c)
}

func TestChangePassword_UserNotFound_ConfusedAsAuthFailed(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	err := svc.ChangePassword(context.Background(), "u-ghost", "any-current", "NewStrongPwd123!")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthFailed, c, "用户不存在混淆为 AUTH_FAILED")
}

func TestChangePassword_EmptyInputs(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.put(newActiveUser(t, "alice"))

	cases := [][3]string{
		{"", "x", "NewStrongPwd123!"},
		{"u-alice", "", "NewStrongPwd123!"},
		{"u-alice", "x", ""},
	}
	for _, tc := range cases {
		err := svc.ChangePassword(context.Background(), tc[0], tc[1], tc[2])
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

func TestChangePassword_DBError_BubblesUp(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.getByIDErr = errx.New(errx.ErrDatabase, "boom")

	err := svc.ChangePassword(context.Background(), "u-alice", knownPlain, "NewStrongPwd123!")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

// === User CRUD ===

func TestCreateUser_Happy(t *testing.T) {
	svc, users, _, _ := setupSvc(t)

	res, err := svc.CreateUser(context.Background(), CreateUserRequest{
		Username: "newbie",
		Email:    "newbie@example.com",
		Role:     domain.RoleProjectAdmin,
		TenantID: "11111111-1111-1111-1111-111111111111",
	})
	require.NoError(t, err)
	require.NotNil(t, res.User)
	assert.Equal(t, "newbie", res.User.Username)
	assert.Equal(t, domain.RoleProjectAdmin, res.User.Role)
	assert.Equal(t, domain.StatusActive, res.User.Status)
	assert.True(t, res.User.MustChangePassword)
	assert.Empty(t, res.User.PasswordHash, "返给 caller 时不应携带 hash")

	require.Len(t, res.TemporaryPassword, generatedTempPasswordLen)

	// repo 里 hash 已存（用 GetByUsername 验证）
	stored := users.users[res.User.ID]
	require.NotNil(t, stored)
	ok, _ := domain.VerifyPassword(res.TemporaryPassword, stored.PasswordHash)
	assert.True(t, ok, "服务端生成的临时密码必须能 verify")
}

func TestCreateUser_WithProvidedPassword(t *testing.T) {
	svc, _, _, _ := setupSvc(t)

	res, err := svc.CreateUser(context.Background(), CreateUserRequest{
		Username:        "alice2",
		Email:           "alice2@example.com",
		Role:            domain.RoleProjectAdmin,
		TenantID:        "11111111-1111-1111-1111-111111111111",
		InitialPassword: "ProvidedStrongPwd1!",
	})
	require.NoError(t, err)
	assert.Equal(t, "ProvidedStrongPwd1!", res.TemporaryPassword,
		"提供密码时回吐同一明文")
}

func TestCreateUser_TooWeakPassword(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.CreateUser(context.Background(), CreateUserRequest{
		Username:        "alice3",
		Email:           "alice3@example.com",
		Role:            domain.RoleProjectAdmin,
		TenantID:        "11111111-1111-1111-1111-111111111111",
		InitialPassword: "short",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthPasswordTooWeak, c)
}

func TestCreateUser_BadUsername(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	_, err := svc.CreateUser(context.Background(), CreateUserRequest{
		Username: "Bad-Case",
		Email:    "x@example.com",
		Role:     domain.RoleProjectAdmin,
		TenantID: "11111111-1111-1111-1111-111111111111",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestCreateUser_TenantInconsistency(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	// SuperAdmin 但带 tenant_id → 应拒
	_, err := svc.CreateUser(context.Background(), CreateUserRequest{
		Username: "rogue",
		Email:    "rogue@example.com",
		Role:     domain.RoleSuperAdmin,
		TenantID: "11111111-1111-1111-1111-111111111111",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === ListUsers / GetUser ===

func TestListUsers_PaginationAndFilters(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	for _, n := range []string{"alice", "bob", "carol"} {
		users.put(newActiveUser(t, n))
	}
	dis := newActiveUser(t, "dave")
	dis.Status = domain.StatusDisabled
	users.put(dis)

	// 默认分页：4 全显
	res, err := svc.ListUsers(context.Background(), ListUsersRequest{})
	require.NoError(t, err)
	assert.Equal(t, 4, res.Total)
	assert.Len(t, res.Users, 4)
	for _, u := range res.Users {
		assert.Empty(t, u.PasswordHash, "List 必须清空 hash")
	}

	// 仅 active
	res, err = svc.ListUsers(context.Background(), ListUsersRequest{Status: domain.StatusActive})
	require.NoError(t, err)
	assert.Equal(t, 3, res.Total)
}

func TestListUsers_PageSizeClampedToMax(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	users.put(newActiveUser(t, "x"))

	res, err := svc.ListUsers(context.Background(), ListUsersRequest{PageSize: 9999})
	require.NoError(t, err)
	assert.Equal(t, listUsersMaxPageSize, res.PageSize)
}

func TestGetUser_HappyAndNotFound(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)

	got, err := svc.GetUser(context.Background(), u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alice", got.Username)
	assert.Empty(t, got.PasswordHash)

	_, err = svc.GetUser(context.Background(), "u-ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

// === Enable / Disable ===

func TestEnableDisableUser(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)
	originalTV := u.TokenVersion

	require.NoError(t, svc.DisableUser(context.Background(), u.ID))
	assert.Equal(t, domain.StatusDisabled, u.Status)
	assert.Equal(t, originalTV+1, u.TokenVersion, "Disable 应 tv++")

	require.NoError(t, svc.EnableUser(context.Background(), u.ID))
	assert.Equal(t, domain.StatusActive, u.Status)
}

// === ResetPassword ===

func TestResetPassword_GeneratesAndBumps(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)
	originalHash := u.PasswordHash
	originalTV := u.TokenVersion

	plain, err := svc.ResetPassword(context.Background(), u.ID)
	require.NoError(t, err)
	require.Len(t, plain, generatedTempPasswordLen)

	stored := users.users[u.ID]
	assert.NotEqual(t, originalHash, stored.PasswordHash, "hash 应更换")
	assert.Equal(t, originalTV+1, stored.TokenVersion, "tv 应 +1")
	assert.True(t, stored.MustChangePassword, "重置后必须强制改密")

	ok, _ := domain.VerifyPassword(plain, stored.PasswordHash)
	assert.True(t, ok)
}

// === ForceLogout ===

func TestForceLogout_BumpsTV(t *testing.T) {
	svc, users, _, _ := setupSvc(t)
	u := newActiveUser(t, "alice")
	users.put(u)
	originalTV := u.TokenVersion

	require.NoError(t, svc.ForceLogout(context.Background(), u.ID))
	assert.Equal(t, originalTV+1, u.TokenVersion)
	assert.Equal(t, domain.StatusActive, u.Status, "ForceLogout 不应改 status")
}

func TestUserCRUD_EmptyIDs(t *testing.T) {
	svc, _, _, _ := setupSvc(t)
	ctx := context.Background()
	ops := []func() error{
		func() error { return svc.EnableUser(ctx, "  ") },
		func() error { return svc.DisableUser(ctx, "  ") },
		func() error { return svc.ForceLogout(ctx, "  ") },
		func() error { _, err := svc.ResetPassword(ctx, "  "); return err },
		func() error { _, err := svc.GetUser(ctx, "  "); return err },
	}
	for _, op := range ops {
		err := op()
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

// 静态断言 — 确认 mock 实现了接口。
var _ = func() bool {
	var _ = newMockUserRepo()
	return strings.HasPrefix(authAPIKeyPrefix, "rmk_")
}()
