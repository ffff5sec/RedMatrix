// Package repo finding 模块的持久层接口（PR-S26）。
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/finding/domain"
)

// Page 通用分页。
type Page struct {
	Page     int
	PageSize int
}

// FindingFilter ListFindings 查询过滤。
type FindingFilter struct {
	TenantID    string
	ProjectID   string   // 空 = 不限项目；非空 = 精确匹配
	ProjectIDs  []string // PA 路径多 project（OR 匹配）
	Status      string
	Severity    string
	AssigneeID  string
	Keyword     string // title/host ILIKE
	MinSeverity string // ≥ minSeverity 比较
}

// FindingRepository findings 表持久层。
type FindingRepository interface {
	// Upsert 按 (tenant_id, project_id, dedup_key) 唯一索引插入或更新（last_seen + occurrence_count）。
	// 已存在 → 仅刷新 last_seen_at + occurrence_count++，不改 status / assignee；返回 (existing, false)。
	// 新建 → 返回 (new, true)。
	Upsert(ctx context.Context, f *domain.Finding) (*domain.Finding, bool, error)
	GetByID(ctx context.Context, id string) (*domain.Finding, error)
	List(ctx context.Context, filter FindingFilter, page Page) ([]*domain.Finding, int, error)
	// UpdateStatus 推进状态机；不校转移合法（service 层校）。
	UpdateStatus(ctx context.Context, id string, status domain.FindingStatus) error
	// UpdateAssignee 设置 assignee；nil → 取消。
	UpdateAssignee(ctx context.Context, id string, assigneeID *string) error
	SoftDelete(ctx context.Context, id string) error
}

// EventRepository finding_events 表持久层。
type EventRepository interface {
	Insert(ctx context.Context, e *domain.FindingEvent) error
	ListByFinding(ctx context.Context, findingID string) ([]*domain.FindingEvent, error)
}
