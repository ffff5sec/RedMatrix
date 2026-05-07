package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
)

// AllowedNodesRepository 是 project_allowed_nodes 表的持久层接口（LLD 11 §3.4 / §6）。
//
// 关键语义：
//   - 表中 project_id 无任何行 → 该项目所有节点可用（隐含 ALL）
//   - 表中 project_id 有行 → 仅这些 node_id 可用（白名单）
//
// 错误约定：
//   - DB 故障 → ErrDatabase 包装
//   - 校验由 service 层做（项目 / 节点 tenant 一致性 / status 等）
type AllowedNodesRepository interface {
	// Set 全量替换项目白名单（事务内 DELETE + INSERT）。
	// nodeIDs 为空切片 → 显式 "禁用所有节点" 模式（IsAllowed 全返 false，
	// 与 "未设置" 即 ALL 完全相反；service 层调用前应明确语义）。
	//
	// MVP：service.SetProjectAllowedNodes 不会传空切片走"禁用所有"语义，
	// 而是要求 caller 显式调 ClearAll 或选定具体 node 列表；本接口保持灵活。
	Set(ctx context.Context, projectID string, nodeIDs []string, addedBy string) error

	// ClearAll 删除项目所有白名单条目；调用后该项目所有节点可用（恢复 ALL 默认）。
	ClearAll(ctx context.Context, projectID string) error

	// Get 返回项目当前白名单。表中无该 project_id 任何行 → AllNodes=true。
	Get(ctx context.Context, projectID string) (domain.AllowedNodes, error)

	// IsAllowed 由 Scan 模块调用：项目 + 节点 → 是否被允许。
	// project 无白名单 → true；project 有白名单 → 仅查 node_id 是否在表中。
	IsAllowed(ctx context.Context, projectID, nodeID string) (bool, error)
}
