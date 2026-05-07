package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validMember() *ProjectMember {
	return &ProjectMember{
		ProjectID: "00000000-0000-0000-0000-00000000aaaa",
		UserID:    "00000000-0000-0000-0000-00000000bbbb",
		TenantID:  "00000000-0000-0000-0000-000000000001",
	}
}

func TestProjectMember_ValidateForCreate_Happy(t *testing.T) {
	require.NoError(t, validMember().ValidateForCreate())
}

func TestProjectMember_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ProjectMember)
	}{
		{"empty project_id", func(m *ProjectMember) { m.ProjectID = "" }},
		{"empty user_id", func(m *ProjectMember) { m.UserID = "" }},
		{"empty tenant_id", func(m *ProjectMember) { m.TenantID = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validMember()
			tc.mut(m)
			err := m.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestProjectMember_NilReceiver(t *testing.T) {
	var m *ProjectMember
	require.Error(t, m.ValidateForCreate())
}
