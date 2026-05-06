package tenancy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// === mock repo ===

type mockAccountRepo struct {
	bySlug      map[string]*domain.Account
	byID        map[string]*domain.Account
	insertErr   error
	getErr      error
	insertCalls int
}

func newMockRepo() *mockAccountRepo {
	return &mockAccountRepo{
		bySlug: map[string]*domain.Account{},
		byID:   map[string]*domain.Account{},
	}
}

func (m *mockAccountRepo) Insert(_ context.Context, a *domain.Account) error {
	m.insertCalls++
	if m.insertErr != nil {
		return m.insertErr
	}
	if err := a.ValidateForCreate(); err != nil {
		return err
	}
	if _, dup := m.bySlug[a.Slug]; dup {
		return errx.New(errx.ErrAccountSlugExists, "dup")
	}
	if a.ID == "" {
		a.ID = "id-" + a.Slug
	}
	m.bySlug[a.Slug] = a
	m.byID[a.ID] = a
	return nil
}
func (m *mockAccountRepo) GetByID(_ context.Context, id string) (*domain.Account, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	a, ok := m.byID[id]
	if !ok {
		return nil, errx.New(errx.ErrAccountNotFound, "not found")
	}
	return a, nil
}
func (m *mockAccountRepo) GetBySlug(_ context.Context, slug string) (*domain.Account, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	a, ok := m.bySlug[slug]
	if !ok {
		return nil, errx.New(errx.ErrAccountNotFound, "not found")
	}
	return a, nil
}
func (m *mockAccountRepo) ListActive(context.Context) ([]*domain.Account, error) {
	return nil, errors.New("not impl")
}

// === Tests ===

func TestBootstrap_CreatesDefaultWhenAbsent(t *testing.T) {
	m := newMockRepo()

	res, err := Bootstrap(context.Background(), m, BootstrapConfig{})
	require.NoError(t, err)
	require.True(t, res.Created)
	require.NotNil(t, res.Account)

	assert.Equal(t, DefaultAccountID, res.Account.ID)
	assert.Equal(t, DefaultAccountSlug, res.Account.Slug)
	assert.Equal(t, DefaultAccountDisplayName, res.Account.DisplayName)
	assert.Equal(t, domain.AccountActive, res.Account.Status)
	assert.Equal(t, 1, m.insertCalls)
}

func TestBootstrap_IdempotentSkipWhenExists(t *testing.T) {
	m := newMockRepo()

	// 预置默认 account
	require.NoError(t, m.Insert(context.Background(), &domain.Account{
		ID:          DefaultAccountID,
		Slug:        DefaultAccountSlug,
		DisplayName: DefaultAccountDisplayName,
		Status:      domain.AccountActive,
	}))
	beforeCalls := m.insertCalls

	res, err := Bootstrap(context.Background(), m, BootstrapConfig{})
	require.NoError(t, err)
	assert.False(t, res.Created)
	assert.Equal(t, DefaultAccountID, res.Account.ID)
	assert.Equal(t, beforeCalls, m.insertCalls, "已存在时不应 Insert")
}

func TestBootstrap_CustomConfig(t *testing.T) {
	m := newMockRepo()

	cfg := BootstrapConfig{
		Slug:        "alpha",
		DisplayName: "Alpha Co",
		FixedID:     "00000000-0000-0000-0000-0000000000aa",
	}
	res, err := Bootstrap(context.Background(), m, cfg)
	require.NoError(t, err)
	require.True(t, res.Created)
	assert.Equal(t, "alpha", res.Account.Slug)
	assert.Equal(t, "Alpha Co", res.Account.DisplayName)
	assert.Equal(t, cfg.FixedID, res.Account.ID)
}

func TestBootstrap_DBErrorBubblesUp(t *testing.T) {
	m := newMockRepo()
	m.getErr = errx.New(errx.ErrDatabase, "boom")

	_, err := Bootstrap(context.Background(), m, BootstrapConfig{})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrDatabase, c)
}

func TestBootstrap_NilRepo(t *testing.T) {
	_, err := Bootstrap(context.Background(), nil, BootstrapConfig{})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}
