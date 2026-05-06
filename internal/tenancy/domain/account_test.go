package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validAccount() *Account {
	return &Account{
		Slug:        "default",
		DisplayName: "RedMatrix",
		Plan:        "standard",
		Status:      AccountActive,
	}
}

func TestAccount_ValidateForCreate_Happy(t *testing.T) {
	require.NoError(t, validAccount().ValidateForCreate())
}

func TestAccount_ValidateForCreate_Defaults(t *testing.T) {
	a := &Account{Slug: "alpha-1", DisplayName: "Alpha"}
	require.NoError(t, a.ValidateForCreate())
	assert.Equal(t, AccountActive, a.Status, "Status 缺省应填 active")
	assert.Equal(t, "standard", a.Plan, "Plan 缺省应填 standard")
}

func TestAccount_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Account)
	}{
		{"slug 太短", func(a *Account) { a.Slug = "ab" }},
		{"slug 太长", func(a *Account) { a.Slug = strings.Repeat("a", 33) }},
		{"slug 含大写", func(a *Account) { a.Slug = "Default" }},
		{"slug 含空格", func(a *Account) { a.Slug = "de fault" }},
		{"slug 空", func(a *Account) { a.Slug = "" }},
		{"display_name 空", func(a *Account) { a.DisplayName = "" }},
		{"display_name 超长", func(a *Account) { a.DisplayName = strings.Repeat("x", 129) }},
		{"status 非法", func(a *Account) { a.Status = AccountStatus("BOGUS") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAccount()
			tc.mut(a)
			err := a.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestAccount_ValidateForCreate_NilReceiver(t *testing.T) {
	var a *Account
	err := a.ValidateForCreate()
	require.Error(t, err)
}

func TestAccount_IsActive(t *testing.T) {
	a := validAccount()
	assert.True(t, a.IsActive())

	a.Status = AccountSuspended
	assert.False(t, a.IsActive())

	a.Status = AccountActive
	now := time.Now()
	a.DeletedAt = &now
	assert.False(t, a.IsActive(), "软删后即使 status=active 也不算活")

	var nilA *Account
	assert.False(t, nilA.IsActive())
}

func TestAccountStatus_Valid(t *testing.T) {
	for _, s := range []AccountStatus{AccountActive, AccountSuspended, AccountDisabled} {
		assert.True(t, s.Valid())
	}
	assert.False(t, AccountStatus("bogus").Valid())
}
