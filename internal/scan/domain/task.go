// Package domain 是 scan 模块的领域类型（PR-S1）。
//
// MVP 范围：仅 ScanTask 元数据 + 状态机。后续扩 task_assignments / results 时
// 再加 Assignment / Result 等类型，保持本文件聚焦。
package domain

import (
	"strings"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// cronParser 用 robfig/cron 默认 5 字段解析器（与 Linux crontab 一致）。
// 包级单例避免每次 Parse 时构造。
var cronParser = cron.NewParser(
	cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow,
)

// TaskStatus 是 ScanTask 状态机 5 状态。
type TaskStatus string

const (
	TaskPending   TaskStatus = "pending"   // 已创建未分发
	TaskRunning   TaskStatus = "running"   // 至少一个 Agent 拉取了
	TaskCompleted TaskStatus = "completed" // 全部 Agent 上报成功结束
	TaskFailed    TaskStatus = "failed"    // 任意 Agent 报错或超时
	TaskCanceled  TaskStatus = "canceled"  // 用户主动取消
)

// Valid 判定 status 是否合法值。
func (s TaskStatus) Valid() bool {
	switch s {
	case TaskPending, TaskRunning, TaskCompleted, TaskFailed, TaskCanceled:
		return true
	}
	return false
}

// IsTerminal 终态：completed / failed / canceled。终态不允许再转移。
func (s TaskStatus) IsTerminal() bool {
	return s == TaskCompleted || s == TaskFailed || s == TaskCanceled
}

// TaskKind 任务类型；与 schema CHECK 约束一致。
type TaskKind string

const (
	KindPortScan    TaskKind = "port_scan"
	KindWebCrawl    TaskKind = "web_crawl"
	KindSubdomain   TaskKind = "subdomain"
	KindFingerprint TaskKind = "fingerprint"
	KindVulnScan    TaskKind = "vuln_scan" // PR-S21
)

func (k TaskKind) Valid() bool {
	switch k {
	case KindPortScan, KindWebCrawl, KindSubdomain, KindFingerprint, KindVulnScan:
		return true
	}
	return false
}

// TargetKind 目标类型；用于前端渲染图标 + agent 选 plugin 时分流。
type TargetKind string

const (
	TargetHost TargetKind = "host"
	TargetIP   TargetKind = "ip"
	TargetCIDR TargetKind = "cidr"
	TargetURL  TargetKind = "url"
)

func (k TargetKind) Valid() bool {
	switch k {
	case TargetHost, TargetIP, TargetCIDR, TargetURL:
		return true
	}
	return false
}

// ScheduleKind MVP 仅 immediate（创建即可派发）；cron 待 PR-S2+。
type ScheduleKind string

const (
	ScheduleImmediate ScheduleKind = "immediate"
	ScheduleCron      ScheduleKind = "cron"
)

func (s ScheduleKind) Valid() bool {
	switch s {
	case ScheduleImmediate, ScheduleCron:
		return true
	}
	return false
}

// ValidCronExpr 用 robfig/cron 标准 5 字段 parser 校验表达式合法性（PR-S12）。
// 仅在 schedule_kind=cron 时调用。空字串返 false。
func ValidCronExpr(expr string) bool {
	if expr == "" {
		return false
	}
	_, err := cronParser.Parse(expr)
	return err == nil
}

// TaskNameMaxLen 与 schema VARCHAR(128) 一致。
const TaskNameMaxLen = 128

// ScanTask 扫描任务领域实体（与 schema 一一对应）。
type ScanTask struct {
	ID        string
	TenantID  string
	ProjectID string
	Name      string
	Kind      TaskKind
	// Target 是单 target 形态；批量场景下 Targets 非空时以 Targets 为准（PR-S22）。
	// 兼容老调用：单 target 时仍写 Target；service 会在 Targets 空时回填 [Target]。
	Target     string
	Targets    []string
	TargetKind TargetKind
	Status     TaskStatus

	ScheduleKind ScheduleKind
	CronExpr     string

	Settings map[string]any

	// SourceTaskID（PR-S15）：cron 模板触发的实例 / Retry 重派的实例指回原 task。
	// nil = 用户手动创建。FK ON DELETE SET NULL，所以源被删后自动断链。
	SourceTaskID *string

	// SuiteRunID（PR-S23）：套件展开生成的子 task 指回 suite_run。
	// nil = 独立 task（非套件路径）。FK ON DELETE SET NULL。
	SuiteRunID *string

	CreatedBy  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	StartedAt  *time.Time
	FinishedAt *time.Time
	DeletedAt  *time.Time
}

// IsActive 状态机非终态 + 未软删。
func (t *ScanTask) IsActive() bool {
	return t != nil && !t.IsDeleted() && !t.Status.IsTerminal()
}

// IsDeleted 软删后所有 RPC 都返 NotFound。
func (t *ScanTask) IsDeleted() bool {
	return t != nil && t.DeletedAt != nil
}

// CanCancel 当前 status 允许 → canceled 转移（pending / running 可，终态不可）。
func (t *ScanTask) CanCancel() bool {
	return t != nil && (t.Status == TaskPending || t.Status == TaskRunning)
}

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (t *ScanTask) ValidateForCreate() error {
	if t == nil {
		return errx.New(errx.ErrInvalidInput, "scan_task is nil")
	}
	if strings.TrimSpace(t.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_task.tenant_id 不能为空")
	}
	if strings.TrimSpace(t.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_task.project_id 不能为空")
	}
	if strings.TrimSpace(t.Name) == "" {
		return errx.New(errx.ErrInvalidInput, "scan_task.name 不能为空")
	}
	if len(t.Name) > TaskNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "scan_task.name 超出最大长度").
			WithFields("max", TaskNameMaxLen)
	}
	if !t.Kind.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "scan_task.kind 不合法").
			WithFields("got", string(t.Kind))
	}
	if strings.TrimSpace(t.Target) == "" {
		return errx.New(errx.ErrTaskNoTargets, "scan_task.target 不能为空")
	}
	if !t.TargetKind.Valid() {
		return errx.New(errx.ErrInvalidInput, "scan_task.target_kind 不合法").
			WithFields("got", string(t.TargetKind))
	}
	if t.Status == "" {
		t.Status = TaskPending
	}
	if !t.Status.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "scan_task.status 不合法").
			WithFields("got", string(t.Status))
	}
	if t.ScheduleKind == "" {
		t.ScheduleKind = ScheduleImmediate
	}
	if !t.ScheduleKind.Valid() {
		return errx.New(errx.ErrInvalidInput, "scan_task.schedule_kind 不合法").
			WithFields("got", string(t.ScheduleKind))
	}
	if t.ScheduleKind == ScheduleCron {
		if strings.TrimSpace(t.CronExpr) == "" {
			return errx.New(errx.ErrTaskCronInvalid, "schedule_kind=cron 时 cron_expr 必填")
		}
		if !ValidCronExpr(t.CronExpr) {
			return errx.New(errx.ErrTaskCronInvalid, "cron_expr 不合法（标准 5 字段）").
				WithFields("expr", t.CronExpr)
		}
	}
	if t.Settings == nil {
		t.Settings = map[string]any{}
	}
	return nil
}
