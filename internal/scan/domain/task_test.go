package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validTask() *ScanTask {
	return &ScanTask{
		TenantID:   "00000000-0000-0000-0000-000000000001",
		ProjectID:  "00000000-0000-0000-0000-000000000aaa",
		Name:       "demo port scan",
		Kind:       KindPortScan,
		Target:     "192.168.1.0/24",
		TargetKind: TargetCIDR,
	}
}

func TestValidateForCreate_Happy(t *testing.T) {
	tk := validTask()
	require.NoError(t, tk.ValidateForCreate())
	assert.Equal(t, TaskPending, tk.Status, "status 缺省 pending")
	assert.Equal(t, ScheduleImmediate, tk.ScheduleKind, "schedule 缺省 immediate")
	assert.NotNil(t, tk.Settings, "settings 缺省非 nil")
}

func TestValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*ScanTask)
		code errx.Code
	}{
		{"empty tenant", func(t *ScanTask) { t.TenantID = "" }, errx.ErrInvalidInput},
		{"empty project", func(t *ScanTask) { t.ProjectID = "" }, errx.ErrInvalidInput},
		{"empty name", func(t *ScanTask) { t.Name = "" }, errx.ErrInvalidInput},
		{"name 超长", func(t *ScanTask) {
			t.Name = string(make([]byte, TaskNameMaxLen+1))
			for i := range t.Name {
				_ = i
			}
			t.Name = ""
			for range TaskNameMaxLen + 1 {
				t.Name += "x"
			}
		}, errx.ErrInvalidInput},
		{"kind 非法", func(t *ScanTask) { t.Kind = "bogus" }, errx.ErrTaskInvalidState},
		{"target 空", func(t *ScanTask) { t.Target = "" }, errx.ErrTaskNoTargets},
		{"target_kind 非法", func(t *ScanTask) { t.TargetKind = "moon" }, errx.ErrInvalidInput},
		{"cron schedule 缺 expr", func(t *ScanTask) {
			t.ScheduleKind = ScheduleCron
			t.CronExpr = ""
		}, errx.ErrTaskCronInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tk := validTask()
			tc.mut(tk)
			err := tk.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, tc.code, c)
		})
	}
}

func TestStatusTransitions(t *testing.T) {
	now := time.Now()
	tk := &ScanTask{Status: TaskPending}
	assert.True(t, tk.IsActive())
	assert.True(t, tk.CanCancel())

	tk.Status = TaskRunning
	assert.True(t, tk.CanCancel())

	tk.Status = TaskCompleted
	assert.False(t, tk.CanCancel())
	assert.False(t, tk.IsActive())

	tk.Status = TaskRunning
	tk.DeletedAt = &now
	assert.False(t, tk.IsActive(), "软删的 task 即便 running 也算 inactive")
}

func TestNilSafe(t *testing.T) {
	var tk *ScanTask
	require.Error(t, tk.ValidateForCreate())
	assert.False(t, tk.IsActive())
	assert.False(t, tk.CanCancel())
	assert.False(t, tk.IsDeleted())
}

func TestEnumsValidity(t *testing.T) {
	for _, s := range []TaskStatus{TaskPending, TaskRunning, TaskCompleted, TaskFailed, TaskCanceled} {
		assert.True(t, s.Valid())
	}
	assert.False(t, TaskStatus("bogus").Valid())
	assert.True(t, TaskCompleted.IsTerminal())
	assert.False(t, TaskRunning.IsTerminal())

	for _, k := range []TaskKind{KindPortScan, KindWebCrawl, KindSubdomain, KindFingerprint} {
		assert.True(t, k.Valid())
	}
	for _, k := range []TargetKind{TargetHost, TargetIP, TargetCIDR, TargetURL} {
		assert.True(t, k.Valid())
	}
	for _, k := range []ScheduleKind{ScheduleImmediate, ScheduleCron} {
		assert.True(t, k.Valid())
	}
}
