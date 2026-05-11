// Package domain：scan 模块领域类型 PR-S23 扫描套件（pipeline）。
//
// ScanSuite 是套件模板：一组 TaskKind + 默认 settings。
// ScanSuiteRun 是一次 RunSuite 实例：targets[] + 聚合 status。
// 子 task 通过 suite_run_id 反查 run；run 通过子 task status 反推自己 status。
package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// SuiteNameMaxLen 与 schema VARCHAR(128) 一致。
const SuiteNameMaxLen = 128

// SuiteRunStatus 6 状态机；与 schema CHECK 一致。
type SuiteRunStatus string

const (
	SuiteRunPending       SuiteRunStatus = "pending"        // 所有子 task 仍 pending
	SuiteRunRunning       SuiteRunStatus = "running"        // 任意子 task pulled/running
	SuiteRunCompleted     SuiteRunStatus = "completed"      // 全部子 task completed
	SuiteRunPartialFailed SuiteRunStatus = "partial_failed" // 至少 1 个 failed + 至少 1 个 completed
	SuiteRunFailed        SuiteRunStatus = "failed"         // 全部子 task failed
	SuiteRunCanceled      SuiteRunStatus = "canceled"       // 全部子 task canceled
)

// Valid 判定 status 是否合法值。
func (s SuiteRunStatus) Valid() bool {
	switch s {
	case SuiteRunPending, SuiteRunRunning, SuiteRunCompleted,
		SuiteRunPartialFailed, SuiteRunFailed, SuiteRunCanceled:
		return true
	}
	return false
}

// IsTerminal 终态：completed / partial_failed / failed / canceled 不再变。
func (s SuiteRunStatus) IsTerminal() bool {
	return s == SuiteRunCompleted || s == SuiteRunPartialFailed ||
		s == SuiteRunFailed || s == SuiteRunCanceled
}

// ScanSuite 套件模板。
type ScanSuite struct {
	ID       string
	TenantID string
	// ProjectID nil = 跨项目（同租户内所有 PA 可见 + 可用）
	ProjectID  *string
	Name       string
	Kinds      []TaskKind
	TargetKind TargetKind
	// DefaultSettings: {"port_scan": {...}, "nuclei": {...}} —— per-kind 覆盖
	DefaultSettings map[string]any

	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// ValidateForCreate INSERT 前的全部域内规则。
func (s *ScanSuite) ValidateForCreate() error {
	if s == nil {
		return errx.New(errx.ErrInvalidInput, "scan_suite is nil")
	}
	if strings.TrimSpace(s.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_suite.tenant_id 不能为空")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_suite.name 不能为空")
	}
	if len(s.Name) > SuiteNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "scan_suite.name 超出最大长度").
			WithFields("max", SuiteNameMaxLen)
	}
	if len(s.Kinds) == 0 {
		return errx.New(errx.ErrInvalidInput, "scan_suite.kinds 至少 1 个")
	}
	seen := make(map[TaskKind]struct{}, len(s.Kinds))
	for _, k := range s.Kinds {
		if !k.Valid() {
			return errx.New(errx.ErrTaskInvalidState, "scan_suite.kinds 含非法 kind").
				WithFields("got", string(k))
		}
		if _, dup := seen[k]; dup {
			return errx.New(errx.ErrInvalidInput, "scan_suite.kinds 含重复 kind").
				WithFields("kind", string(k))
		}
		seen[k] = struct{}{}
	}
	if !s.TargetKind.Valid() {
		return errx.New(errx.ErrInvalidInput, "scan_suite.target_kind 不合法").
			WithFields("got", string(s.TargetKind))
	}
	if s.DefaultSettings == nil {
		s.DefaultSettings = map[string]any{}
	}
	return nil
}

// IsDeleted 软删后所有 RPC 都返 NotFound。
func (s *ScanSuite) IsDeleted() bool {
	return s != nil && s.DeletedAt != nil
}

// ScanSuiteRun 一次 RunSuite 实例。
type ScanSuiteRun struct {
	ID         string
	SuiteID    string
	TenantID   string
	ProjectID  string
	Targets    []string
	Status     SuiteRunStatus
	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	FinishedAt *time.Time
}

// ValidateForCreate INSERT 前校验。
func (r *ScanSuiteRun) ValidateForCreate() error {
	if r == nil {
		return errx.New(errx.ErrInvalidInput, "scan_suite_run is nil")
	}
	if strings.TrimSpace(r.SuiteID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_suite_run.suite_id 不能为空")
	}
	if strings.TrimSpace(r.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_suite_run.tenant_id 不能为空")
	}
	if strings.TrimSpace(r.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_suite_run.project_id 不能为空")
	}
	if len(r.Targets) == 0 {
		return errx.New(errx.ErrTaskNoTargets, "scan_suite_run.targets 至少 1 个")
	}
	if r.Status == "" {
		r.Status = SuiteRunPending
	}
	if !r.Status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "scan_suite_run.status 不合法").
			WithFields("got", string(r.Status))
	}
	return nil
}
