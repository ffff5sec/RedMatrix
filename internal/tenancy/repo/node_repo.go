package repo

import (
	"context"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// NodeRepository 是 nodes 表的持久层接口（LLD 11 §3.5）。
//
// 错误约定：
//   - GetByID 找不到 / 已 soft-deleted → ErrNodeNotFound
//   - Insert name 在租户内重复 → ErrNodeNameExists
//   - 其他 DB 故障 → ErrDatabase 包装
type NodeRepository interface {
	// Insert 写入新 node 行；要求 n.ValidateForCreate 已通过。
	Insert(ctx context.Context, n *domain.Node) error

	// GetByID 按 UUID 查；不返回已软删的行。
	GetByID(ctx context.Context, id string) (*domain.Node, error)

	// List 列租户内节点（排除 soft-deleted），分页 + 状态过滤。
	List(ctx context.Context, filter NodeFilter, page Page) ([]*domain.Node, int, error)

	// UpdateStatus 改 status（含 disabled / online / offline）。幂等。
	UpdateStatus(ctx context.Context, id string, status domain.NodeStatus) error

	// TouchLastSeen 写心跳：更新 last_seen_at = ts；若原状态是 pending / offline
	// 则同步置为 online。disabled / 软删 行不动（避免被 Heartbeat 复活）。
	//
	// 行不存在 / disabled / 软删 → 返 ErrNodeNotFound（caller 让 Agent 退出循环）。
	TouchLastSeen(ctx context.Context, id string, ts time.Time) error

	// SoftDelete 把 deleted_at = now()；后续查询全部排除。
	SoftDelete(ctx context.Context, id string) error
}

// NodeFilter 是 List 查询的可选过滤条件。
type NodeFilter struct {
	TenantID string            // 空 = 跨租户
	Status   domain.NodeStatus // 空 = 不过滤
	Keyword  string            // 空 = 不过滤；name ILIKE 子串
}
