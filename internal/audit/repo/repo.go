// Package repo audit 持久层接口（PR-S33）。
package repo

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/audit/domain"
)

// LogFilter ListLogs 过滤条件。
type LogFilter struct {
	TenantID     string // 必填（已通过 RBAC 注入）
	ProjectID    string
	ActorUserID  string
	Action       string
	ResourceKind string
	ResourceID   string
	TimeFrom     *time.Time
	TimeTo       *time.Time
}

// Page 分页。
type Page struct {
	Page     int
	PageSize int
}

// Repository audit_logs 持久层。
type Repository interface {
	// Insert 写入单条；caller 保证 PrevHash + Hash 已算好。
	Insert(ctx context.Context, a *domain.AuditLog) error
	// GetByID 取单条（SA-only handler 用）。
	GetByID(ctx context.Context, id string) (*domain.AuditLog, error)
	// LatestHash 取该 tenant 当前最后一条的 hash；用于算下一条的 prev_hash。
	// 无记录 → 返 GenesisPrevHash + ok=false。
	LatestHash(ctx context.Context, tenantID string) (hash string, ok bool, err error)
	// List 过滤 + 分页；ORDER BY created_at DESC。
	List(ctx context.Context, filter LogFilter, page Page) ([]*domain.AuditLog, int, error)
	// ListSegmentASC 校验用：取一段连续 audit 行 ASC（最旧在前）；
	// 用于 VerifyChain RPC，调用方按 created_at ASC 重算 hash。
	ListSegmentASC(ctx context.Context, tenantID string, from, to time.Time, limit int) ([]*domain.AuditLog, error)
}
