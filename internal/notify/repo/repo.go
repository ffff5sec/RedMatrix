// Package repo notify 模块的持久层接口（PR-S25）。
package repo

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
)

// Page 通用分页结构（与 scan/repo.Page 同形，不跨包引用减少依赖）。
type Page struct {
	Page     int
	PageSize int
}

// SubscriptionFilter ListSubscriptions 查询过滤。
type SubscriptionFilter struct {
	TenantID  string // 必填
	ProjectID string // 空 = 含 NULL（tenant-wide）+ 所有项目；非空 = 该项目 + tenant-wide
	Channel   string // 空 = 不过滤
	Keyword   string // name ILIKE
	Enabled   *bool  // nil = 不过滤；非空 = 精确匹配
}

// SubscriptionRepository notification_subscriptions 表持久层。
type SubscriptionRepository interface {
	Insert(ctx context.Context, s *domain.Subscription) error
	GetByID(ctx context.Context, id string) (*domain.Subscription, error)
	List(ctx context.Context, filter SubscriptionFilter, page Page) ([]*domain.Subscription, int, error)
	// Update 更新 name / event_kinds / channel / config / filter / enabled。
	// 不允许改 tenant_id / project_id（创建即定）。
	Update(ctx context.Context, s *domain.Subscription) error
	SoftDelete(ctx context.Context, id string) error
	// ListMatching 给定 event_kind 和 tenant + 可选 project，返回所有 enabled 订阅。
	// project nil = 仅匹配 tenant-wide；非空 = 匹配 project 内 + tenant-wide
	ListMatching(ctx context.Context, tenantID string, projectID *string, eventKind domain.EventKind) ([]*domain.Subscription, error)
}

// DeliveryFilter ListDeliveries 查询过滤。
type DeliveryFilter struct {
	TenantID       string
	ProjectID      string
	SubscriptionID string
	Status         string
	EventKind      string
}

// DeliveryRepository notification_deliveries 表持久层。
type DeliveryRepository interface {
	Insert(ctx context.Context, d *domain.Delivery) error
	GetByID(ctx context.Context, id string) (*domain.Delivery, error)
	List(ctx context.Context, filter DeliveryFilter, page Page) ([]*domain.Delivery, int, error)

	// FetchDue 取 scheduled_at ≤ now 且 status ∈ {pending,failed} 的投递（用于 retry sweeper）。
	// limit 控制单次批量；按 scheduled_at ASC 取最早的。
	FetchDue(ctx context.Context, now time.Time, limit int) ([]*domain.Delivery, error)

	// MarkSent 投递成功：status=sent + sent_at=now。
	MarkSent(ctx context.Context, id string, sentAt time.Time) error
	// MarkFailed 投递失败：status=failed + attempts++ + last_error + scheduled_at=next。
	// next nil → 转 dead。
	MarkFailed(ctx context.Context, id string, lastErr string, next *time.Time) error
}
