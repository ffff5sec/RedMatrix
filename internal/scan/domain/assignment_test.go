package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validAssignment() *TaskAssignment {
	return &TaskAssignment{
		TaskID: "00000000-0000-0000-0000-000000000aaa",
		NodeID: "00000000-0000-0000-0000-000000000bbb",
	}
}

func TestAssignment_ValidateForCreate_Happy(t *testing.T) {
	a := validAssignment()
	require.NoError(t, a.ValidateForCreate())
	assert.Equal(t, AssignmentAssigned, a.Status, "默认 status assigned")
}

func TestAssignment_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*TaskAssignment)
		code errx.Code
	}{
		{"empty task", func(a *TaskAssignment) { a.TaskID = "" }, errx.ErrInvalidInput},
		{"empty node", func(a *TaskAssignment) { a.NodeID = "" }, errx.ErrInvalidInput},
		{"bad status", func(a *TaskAssignment) { a.Status = "bogus" }, errx.ErrTaskInvalidState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := validAssignment()
			tc.mut(a)
			err := a.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, tc.code, c)
		})
	}
}

func TestAssignmentStatus_Validity(t *testing.T) {
	for _, s := range []AssignmentStatus{
		AssignmentAssigned, AssignmentPulled, AssignmentRunning,
		AssignmentCompleted, AssignmentFailed,
	} {
		assert.True(t, s.Valid())
	}
	assert.False(t, AssignmentStatus("bogus").Valid())
	assert.True(t, AssignmentCompleted.IsTerminal())
	assert.True(t, AssignmentFailed.IsTerminal())
	assert.False(t, AssignmentRunning.IsTerminal())
}

func TestAssignment_NilSafe(t *testing.T) {
	var a *TaskAssignment
	require.Error(t, a.ValidateForCreate())
}
