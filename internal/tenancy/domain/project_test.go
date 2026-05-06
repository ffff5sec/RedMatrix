package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validProject() *Project {
	return &Project{
		TenantID: "00000000-0000-0000-0000-000000000001",
		Name:     "demo",
	}
}

func TestProject_ValidateForCreate_Happy(t *testing.T) {
	p := validProject()
	require.NoError(t, p.ValidateForCreate())
	assert.Equal(t, ProjectActive, p.Status, "状态缺省 active")
}

func TestProject_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Project)
	}{
		{"empty tenant", func(p *Project) { p.TenantID = "" }},
		{"empty name", func(p *Project) { p.Name = "" }},
		{"name 超长", func(p *Project) { p.Name = strings.Repeat("x", 129) }},
		{"description 超长", func(p *Project) { p.Description = strings.Repeat("y", 2001) }},
		{"status 非法", func(p *Project) { p.Status = ProjectStatus("bogus") }},
		{"active + archived_at", func(p *Project) {
			t := time.Now()
			p.Status = ProjectActive
			p.ArchivedAt = &t
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validProject()
			tc.mut(p)
			err := p.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestProject_NilReceiver(t *testing.T) {
	var p *Project
	require.Error(t, p.ValidateForCreate())
	assert.False(t, p.IsMutable())
	assert.False(t, p.IsArchived())
	assert.False(t, p.IsDeleted())
}

func TestProject_StateChecks(t *testing.T) {
	p := validProject()
	p.Status = ProjectActive
	assert.True(t, p.IsMutable())
	assert.False(t, p.IsArchived())

	p.Status = ProjectArchived
	assert.False(t, p.IsMutable())
	assert.True(t, p.IsArchived())

	now := time.Now()
	p.DeletedAt = &now
	assert.False(t, p.IsMutable())
	assert.False(t, p.IsArchived())
	assert.True(t, p.IsDeleted())
}

func TestProjectStatus_Valid(t *testing.T) {
	for _, s := range []ProjectStatus{ProjectActive, ProjectArchived} {
		assert.True(t, s.Valid())
	}
	assert.False(t, ProjectStatus("BOGUS").Valid())
}
