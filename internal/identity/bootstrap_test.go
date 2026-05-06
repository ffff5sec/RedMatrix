package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// === mock repo ===

type mockUserRepo struct {
	created     *domain.User
	createErr   error
	countByRole map[domain.Role]int
	countErr    error
	createCalls int
}

func newMock() *mockUserRepo {
	return &mockUserRepo{countByRole: map[domain.Role]int{}}
}

func (m *mockUserRepo) Create(_ context.Context, u *domain.User) error {
	m.createCalls++
	if m.createErr != nil {
		return m.createErr
	}
	if u.ID == "" {
		u.ID = "u-mock"
	}
	m.created = u
	return nil
}
func (m *mockUserRepo) GetByID(context.Context, string) (*domain.User, error) {
	return nil, errors.New("not impl")
}
func (m *mockUserRepo) GetByUsername(context.Context, string) (*domain.User, error) {
	return nil, errors.New("not impl")
}
func (m *mockUserRepo) UpdatePassword(context.Context, string, string, bool) error {
	return errors.New("not impl")
}
func (m *mockUserRepo) UpdateLastLogin(context.Context, string) error {
	return errors.New("not impl")
}
func (m *mockUserRepo) IncrementTokenVersion(context.Context, string) error {
	return errors.New("not impl")
}
func (m *mockUserRepo) UpdateStatus(context.Context, string, domain.Status) error {
	return errors.New("not impl")
}
func (m *mockUserRepo) LogoutAllSessions(context.Context, string) error {
	return errors.New("not impl")
}
func (m *mockUserRepo) CountByRole(_ context.Context, r domain.Role) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return m.countByRole[r], nil
}

// === fixtures ===

func validCfg() BootstrapConfig {
	return BootstrapConfig{
		Username: "admin",
		Email:    "admin@example.com",
		Password: "ProvidedPasswordX1!",
	}
}

// === Tests ===

func TestBootstrap_CreatesSuperAdminWhenNoneExists(t *testing.T) {
	m := newMock()
	cfg := validCfg()

	res, err := Bootstrap(context.Background(), m, cfg)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Created)
	assert.Empty(t, res.GeneratedPassword, "提供了密码不应回吐 generated")

	require.NotNil(t, m.created)
	assert.Equal(t, "admin", m.created.Username)
	assert.Equal(t, "admin@example.com", m.created.Email)
	assert.Equal(t, domain.RoleSuperAdmin, m.created.Role)
	assert.Equal(t, domain.StatusActive, m.created.Status)
	assert.True(t, m.created.MustChangePassword)
	assert.Empty(t, m.created.TenantID, "SuperAdmin tenant_id 必须为空")
	assert.NotEmpty(t, m.created.PasswordHash)
	assert.NotEqual(t, cfg.Password, m.created.PasswordHash, "必须存 hash，不存明文")

	// hash 可被反向校验
	ok, _ := domain.VerifyPassword(cfg.Password, m.created.PasswordHash)
	assert.True(t, ok)
}

func TestBootstrap_GeneratesRandomWhenPasswordEmpty(t *testing.T) {
	m := newMock()
	cfg := validCfg()
	cfg.Password = ""

	res, err := Bootstrap(context.Background(), m, cfg)
	require.NoError(t, err)
	require.True(t, res.Created)
	assert.Len(t, res.GeneratedPassword, randomBootstrapPasswordLen)

	// 生成的密码可登录
	ok, _ := domain.VerifyPassword(res.GeneratedPassword, m.created.PasswordHash)
	assert.True(t, ok)

	// 全字母表内
	for _, c := range res.GeneratedPassword {
		assert.Contains(t, bootstrapPasswordAlphabet, string(c))
	}
}

func TestBootstrap_IdempotentSkipsWhenSuperAdminExists(t *testing.T) {
	m := newMock()
	m.countByRole[domain.RoleSuperAdmin] = 1

	res, err := Bootstrap(context.Background(), m, validCfg())
	require.NoError(t, err)
	assert.False(t, res.Created)
	assert.Equal(t, 0, m.createCalls, "已存在 SuperAdmin 不应再 Create")
}

func TestBootstrap_RejectsTooShortPassword(t *testing.T) {
	m := newMock()
	cfg := validCfg()
	cfg.Password = "short" // < 12

	_, err := Bootstrap(context.Background(), m, cfg)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthPasswordTooWeak, c)
	assert.Equal(t, 0, m.createCalls)
}

func TestBootstrap_RejectsEmptyUsername(t *testing.T) {
	m := newMock()
	cfg := validCfg()
	cfg.Username = "  "

	_, err := Bootstrap(context.Background(), m, cfg)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestBootstrap_RejectsEmptyEmail(t *testing.T) {
	m := newMock()
	cfg := validCfg()
	cfg.Email = ""

	_, err := Bootstrap(context.Background(), m, cfg)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestBootstrap_NilRepo(t *testing.T) {
	_, err := Bootstrap(context.Background(), nil, validCfg())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}

func TestBootstrap_CountErrorBubblesUp(t *testing.T) {
	m := newMock()
	m.countErr = errx.New(errx.ErrDatabase, "boom")

	_, err := Bootstrap(context.Background(), m, validCfg())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

func TestBootstrap_CreateErrorBubblesUp(t *testing.T) {
	m := newMock()
	m.createErr = errx.New(errx.ErrUserUsernameExists, "duplicate")

	_, err := Bootstrap(context.Background(), m, validCfg())
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserUsernameExists, c)
}

// === randomStrongPassword ===

func TestRandomStrongPassword_Distribution(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		p, err := randomStrongPassword(16)
		require.NoError(t, err)
		require.Len(t, p, 16)
		seen[p] = struct{}{}
	}
	assert.Greater(t, len(seen), 195, "200 次内不应碰撞")
}
