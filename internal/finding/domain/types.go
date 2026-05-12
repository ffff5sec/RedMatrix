// Package domain finding 模块的领域类型（PR-S26）。
//
// 范围：
//   - Finding：漏洞工单实体（dedup_key 去重）
//   - FindingEvent：操作流水（状态变更 / 评论 / 指派）
//   - FindingStatus 枚举 + 状态机转移表
package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// FindingStatus 5 状态。
type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"           // 初始：自动创建或手工新建
	FindingTriaged       FindingStatus = "triaged"        // 已分派 / 已认领，未确认
	FindingConfirmed     FindingStatus = "confirmed"      // 已复现 / 已确认
	FindingFalsePositive FindingStatus = "false_positive" // 误报；可 reopen → open
	FindingFixed         FindingStatus = "fixed"          // 已修复；可 reopen → open
)

// Valid 判定 status 合法值。
func (s FindingStatus) Valid() bool {
	switch s {
	case FindingOpen, FindingTriaged, FindingConfirmed, FindingFalsePositive, FindingFixed:
		return true
	}
	return false
}

// allowedTransitions 状态机转移表。
//
//	open          → triaged / false_positive / fixed（小漏洞直接修了的快路径）
//	triaged       → confirmed / false_positive / open（撤回）
//	confirmed     → fixed / false_positive
//	false_positive → open（reopen）
//	fixed         → open（reopen，发现没修好）
var allowedTransitions = map[FindingStatus]map[FindingStatus]bool{
	FindingOpen: {
		FindingTriaged:       true,
		FindingFalsePositive: true,
		FindingFixed:         true,
	},
	FindingTriaged: {
		FindingConfirmed:     true,
		FindingFalsePositive: true,
		FindingOpen:          true,
	},
	FindingConfirmed: {
		FindingFixed:         true,
		FindingFalsePositive: true,
	},
	FindingFalsePositive: {
		FindingOpen: true,
	},
	FindingFixed: {
		FindingOpen: true,
	},
}

// CanTransition 是否允许从 from → to。
func CanTransition(from, to FindingStatus) bool {
	if from == to {
		return false
	}
	if next, ok := allowedTransitions[from]; ok {
		return next[to]
	}
	return false
}

// FindingEventKind 流水事件类型。
type FindingEventKind string

const (
	EventCreated        FindingEventKind = "created"
	EventStatusChange   FindingEventKind = "status_change"
	EventComment        FindingEventKind = "comment"
	EventAssigneeChange FindingEventKind = "assignee_change"
	EventOccurrence     FindingEventKind = "occurrence" // 重复扫到，last_seen 刷新
)

// Valid 判定 event kind 合法。
func (k FindingEventKind) Valid() bool {
	switch k {
	case EventCreated, EventStatusChange, EventComment, EventAssigneeChange, EventOccurrence:
		return true
	}
	return false
}

// Severity 漏洞严重度（与 nuclei 标准一致）。
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid 判定 severity 合法。
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Rank 用于过滤 ≥ minSeverity 比较。
func (s Severity) Rank() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	}
	return 0
}

// FindingTitleMaxLen schema VARCHAR(256) 对齐。
const FindingTitleMaxLen = 256

// HostMaxLen schema VARCHAR(256) 对齐。
const HostMaxLen = 256

// DedupKeyMaxLen schema VARCHAR(256) 对齐。
const DedupKeyMaxLen = 256

// Finding 漏洞工单实体。
type Finding struct {
	ID             string
	TenantID       string
	ProjectID      string
	DedupKey       string  // service 层基于 template + host + project 算
	TemplateID     string  // nuclei slug，例如 "CVE-2021-44228"
	SourceResultID *string // 首次创建时的 scan_result.id
	AssetID        *string

	Severity    Severity
	Title       string
	Host        string
	Description string
	Reference   string

	Status     FindingStatus
	AssigneeID *string

	FirstSeenAt     time.Time
	LastSeenAt      time.Time
	OccurrenceCount int

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// IsDeleted 软删后所有 RPC 返 NotFound。
func (f *Finding) IsDeleted() bool {
	return f != nil && f.DeletedAt != nil
}

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (f *Finding) ValidateForCreate() error {
	if f == nil {
		return errx.New(errx.ErrInvalidInput, "finding is nil")
	}
	if strings.TrimSpace(f.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.tenant_id 不能为空")
	}
	if strings.TrimSpace(f.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.project_id 不能为空")
	}
	if strings.TrimSpace(f.TemplateID) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.template_id 不能为空")
	}
	if strings.TrimSpace(f.Host) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.host 不能为空")
	}
	if len(f.Host) > HostMaxLen {
		return errx.New(errx.ErrInvalidInput, "finding.host 超出最大长度").WithFields("max", HostMaxLen)
	}
	if strings.TrimSpace(f.Title) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.title 不能为空")
	}
	if len(f.Title) > FindingTitleMaxLen {
		return errx.New(errx.ErrInvalidInput, "finding.title 超出最大长度").WithFields("max", FindingTitleMaxLen)
	}
	if !f.Severity.Valid() {
		return errx.New(errx.ErrInvalidInput, "finding.severity 不合法").
			WithFields("got", string(f.Severity))
	}
	if f.Status == "" {
		f.Status = FindingOpen
	}
	if !f.Status.Valid() {
		return errx.New(errx.ErrInvalidInput, "finding.status 不合法").
			WithFields("got", string(f.Status))
	}
	if strings.TrimSpace(f.DedupKey) == "" {
		return errx.New(errx.ErrInvalidInput, "finding.dedup_key 不能为空")
	}
	if len(f.DedupKey) > DedupKeyMaxLen {
		return errx.New(errx.ErrInvalidInput, "finding.dedup_key 超出最大长度").
			WithFields("max", DedupKeyMaxLen)
	}
	return nil
}

// MakeDedupKey 生成 dedup_key（service 用同样规则）。
// dedup_key = template_id + "|" + host（同 tenant_id + project_id 已在 UNIQUE 索引上）。
func MakeDedupKey(templateID, host string) string {
	return strings.TrimSpace(templateID) + "|" + strings.TrimSpace(host)
}

// FindingEvent 流水记录。
type FindingEvent struct {
	ID           string
	FindingID    string
	ActorID      *string // nil = system
	Kind         FindingEventKind
	FromStatus   *FindingStatus
	ToStatus     *FindingStatus
	FromAssignee *string
	ToAssignee   *string
	Body         string
	CreatedAt    time.Time
}
