package domain

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === Role ===

func TestRole_Valid(t *testing.T) {
	for _, r := range []Role{
		RoleSuperAdmin, RoleProjectAdmin, RoleTenantAuditor, RolePlatformAuditor,
	} {
		assert.True(t, r.Valid(), string(r))
	}
	assert.False(t, Role("").Valid())
	assert.False(t, Role("OWNER").Valid())
	assert.False(t, Role("super_admin").Valid()) // 大小写敏感
}

func TestRole_IsCrossTenant(t *testing.T) {
	assert.True(t, RoleSuperAdmin.IsCrossTenant())
	assert.True(t, RolePlatformAuditor.IsCrossTenant())
	assert.False(t, RoleProjectAdmin.IsCrossTenant())
	assert.False(t, RoleTenantAuditor.IsCrossTenant())
}

// === Status ===

func TestStatus_Valid(t *testing.T) {
	for _, s := range []Status{StatusActive, StatusDisabled, StatusPendingDeletion} {
		assert.True(t, s.Valid(), string(s))
	}
	assert.False(t, Status("").Valid())
	assert.False(t, Status("Active").Valid()) // 大小写
}

// === ValidateForCreate — 基础合法路径 ===

func validUser() *User {
	return &User{
		Username:     "alice",
		PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$xxx$yyy",
		Email:        "alice@example.com",
		Role:         RoleProjectAdmin,
		Status:       StatusActive,
		TenantID:     "11111111-1111-1111-1111-111111111111",
	}
}

func TestValidateForCreate_HappyPath(t *testing.T) {
	u := validUser()
	assert.NoError(t, u.ValidateForCreate())
}

func TestValidateForCreate_DefaultsStatus(t *testing.T) {
	u := validUser()
	u.Status = ""
	require.NoError(t, u.ValidateForCreate())
	assert.Equal(t, StatusActive, u.Status)
}

func TestValidateForCreate_NilUser(t *testing.T) {
	var u *User
	err := u.ValidateForCreate()
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === Username 规则 ===

func TestValidateForCreate_UsernameRules(t *testing.T) {
	tests := []struct {
		name string
		u    string
		ok   bool
	}{
		{"valid lowercase", "alice", true},
		{"valid alnum_underscore", "user_123", true},
		{"valid hyphen", "ops-team", true},
		{"valid 3 chars min", "abc", true},
		{"valid 32 chars max", "abcdefghij0123456789abcdefghij01", true},
		{"too short", "ab", false},
		{"too long", "abcdefghij0123456789abcdefghij012", false},
		{"uppercase rejected", "Alice", false},
		{"space rejected", "ali ce", false},
		{"@ rejected", "alice@", false},
		{"dot rejected", "ali.ce", false},
		{"empty rejected", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := validUser()
			u.Username = tt.u
			err := u.ValidateForCreate()
			if tt.ok {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				c, _ := errx.GetCode(err)
				assert.Equal(t, errx.ErrInvalidInput, c)
			}
		})
	}
}

// === Email 校验 ===

func TestValidateForCreate_EmailOptional(t *testing.T) {
	u := validUser()
	u.Email = ""
	assert.NoError(t, u.ValidateForCreate(), "email 可选")
}

func TestValidateForCreate_EmailFormat(t *testing.T) {
	tests := []struct {
		v  string
		ok bool
	}{
		{"alice@example.com", true},
		{"a@b.c", true},
		{"alice", false},
		{"alice@", false},
		{"@example.com", false},
		{"alice@example", false}, // 缺顶级域
	}
	for _, tt := range tests {
		t.Run(tt.v, func(t *testing.T) {
			u := validUser()
			u.Email = tt.v
			err := u.ValidateForCreate()
			if tt.ok {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				c, _ := errx.GetCode(err)
				assert.Equal(t, errx.ErrInvalidFormat, c)
			}
		})
	}
}

// === Tenant 一致性 ===

func TestValidateTenantConsistency_SuperAdminMustNotHaveTenant(t *testing.T) {
	u := validUser()
	u.Role = RoleSuperAdmin
	u.TenantID = "11111111-1111-1111-1111-111111111111"
	err := u.ValidateTenantConsistency()
	require.Error(t, err)
}

func TestValidateTenantConsistency_SuperAdminWithoutTenantOK(t *testing.T) {
	u := validUser()
	u.Role = RoleSuperAdmin
	u.TenantID = ""
	assert.NoError(t, u.ValidateTenantConsistency())
}

func TestValidateTenantConsistency_PlatformAuditorSameAsSuperAdmin(t *testing.T) {
	u := validUser()
	u.Role = RolePlatformAuditor
	u.TenantID = ""
	assert.NoError(t, u.ValidateTenantConsistency())

	u.TenantID = "x"
	assert.Error(t, u.ValidateTenantConsistency())
}

func TestValidateTenantConsistency_ProjectAdminMustHaveTenant(t *testing.T) {
	u := validUser()
	u.Role = RoleProjectAdmin
	u.TenantID = ""
	err := u.ValidateTenantConsistency()
	require.Error(t, err)
}

func TestValidateForCreate_TenantInconsistencyPropagated(t *testing.T) {
	u := validUser()
	u.Role = RoleSuperAdmin // 把 tenant_id 留着 → 不一致
	err := u.ValidateForCreate()
	require.Error(t, err)
	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
}

// === Password Hash 必填 ===

func TestValidateForCreate_PasswordHashEmpty(t *testing.T) {
	u := validUser()
	u.PasswordHash = ""
	err := u.ValidateForCreate()
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestValidateForCreate_PasswordHashOnlyWhitespace(t *testing.T) {
	u := validUser()
	u.PasswordHash = "   "
	err := u.ValidateForCreate()
	require.Error(t, err)
}

// === IsActive ===

func TestIsActive(t *testing.T) {
	u := validUser()
	assert.True(t, u.IsActive())

	u.Status = StatusDisabled
	assert.False(t, u.IsActive())

	var nilU *User
	assert.False(t, nilU.IsActive())
}
