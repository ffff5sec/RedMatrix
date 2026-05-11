package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// AssignmentStatus 派发单 5 状态机。
type AssignmentStatus string

const (
	AssignmentAssigned  AssignmentStatus = "assigned"  // service 派发后立即；agent 未拉
	AssignmentPulled    AssignmentStatus = "pulled"    // agent 拉过；未开跑
	AssignmentRunning   AssignmentStatus = "running"   // agent 上报开跑
	AssignmentCompleted AssignmentStatus = "completed" // agent 上报成功
	AssignmentFailed    AssignmentStatus = "failed"    // agent 上报失败
)

// Valid 判定 status 是否合法值。
func (s AssignmentStatus) Valid() bool {
	switch s {
	case AssignmentAssigned, AssignmentPulled, AssignmentRunning,
		AssignmentCompleted, AssignmentFailed:
		return true
	}
	return false
}

// IsTerminal 终态：completed / failed。
func (s AssignmentStatus) IsTerminal() bool {
	return s == AssignmentCompleted || s == AssignmentFailed
}

// TaskAssignment 派发单领域实体。
type TaskAssignment struct {
	ID     string
	TaskID string
	NodeID string
	Status AssignmentStatus
	// Targets 是 dispatch 时切给本 assignment 的 target 子集（PR-S22 批量目标）。
	// 空表示走老路径（agent 用 task.target 单值）。
	Targets    []string
	AssignedAt time.Time
	PulledAt   *time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	Error      string
}

// ValidateForCreate INSERT 前校验。
func (a *TaskAssignment) ValidateForCreate() error {
	if a == nil {
		return errx.New(errx.ErrInvalidInput, "assignment is nil")
	}
	if strings.TrimSpace(a.TaskID) == "" {
		return errx.New(errx.ErrInvalidInput, "assignment.task_id 不能为空")
	}
	if strings.TrimSpace(a.NodeID) == "" {
		return errx.New(errx.ErrInvalidInput, "assignment.node_id 不能为空")
	}
	if a.Status == "" {
		a.Status = AssignmentAssigned
	}
	if !a.Status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "assignment.status 不合法").
			WithFields("got", string(a.Status))
	}
	return nil
}
