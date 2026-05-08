package domain

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// NodeStatus 是节点状态机 4 状态之一（LLD 11 §3.5）。
type NodeStatus string

const (
	NodePending  NodeStatus = "pending"  // token 已生成，节点未连接（MVP：手动建即此态）
	NodeOnline   NodeStatus = "online"   // Control Plane Session 活跃
	NodeOffline  NodeStatus = "offline"  // Session 断开 > 5s
	NodeDisabled NodeStatus = "disabled" // 人为禁用
)

// Valid 判断 NodeStatus 是否合法值。
func (s NodeStatus) Valid() bool {
	switch s {
	case NodePending, NodeOnline, NodeOffline, NodeDisabled:
		return true
	}
	return false
}

// Node 是 tenancy 模块的节点实体（LLD 11 §3.5）。
type Node struct {
	ID           string
	TenantID     string
	Name         string
	Version      string
	Capabilities []string
	Status       NodeStatus
	LastSeenAt   *time.Time

	CreatedBy string

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// IsActive 状态非 disabled 且未软删（业务可派任务）。
func (n *Node) IsActive() bool {
	return n != nil && n.Status != NodeDisabled && n.DeletedAt == nil
}

// IsOnline 仅 status=online 且活跃。
func (n *Node) IsOnline() bool {
	return n != nil && n.Status == NodeOnline && n.DeletedAt == nil
}

// IsDeleted 软删后所有 RPC 都返 NotFound。
func (n *Node) IsDeleted() bool {
	return n != nil && n.DeletedAt != nil
}

// NodeNameMaxLen 与 schema VARCHAR(64) 一致。
const NodeNameMaxLen = 64

// HeartbeatInterval 是 Agent 心跳期望发包间隔（默认值；后续可下放配置）。
//
// MVP 30s：兼顾"快感知掉线"和"不要把 PG 写穿"。
const HeartbeatInterval = 30 * time.Second

// NodeOfflineGrace 是判定 online→offline 的阈值（2× HeartbeatInterval）。
//
// 给一次丢包冗余；server 侧周期 sweeper 用本常量。
const NodeOfflineGrace = 2 * HeartbeatInterval

// DeriveStatus 从持久化 (Status, LastSeenAt) 推算 "now 此刻应该是什么状态"。
//
// 用途：List 视图实时纠正 stale 状态；周期 sweeper 也用本逻辑。
//
// 规则：
//   - disabled / 软删 / pending（从未连过）→ 原样返
//   - online 但 last_seen_at 距 now > NodeOfflineGrace → 返 offline
//   - 其他 → 原样
func (n *Node) DeriveStatus(now time.Time) NodeStatus {
	if n == nil {
		return ""
	}
	if n.Status == NodeDisabled || n.IsDeleted() {
		return n.Status
	}
	if n.LastSeenAt == nil {
		return n.Status
	}
	if n.Status == NodeOnline && now.Sub(*n.LastSeenAt) > NodeOfflineGrace {
		return NodeOffline
	}
	return n.Status
}

// ValidateForCreate 跑 INSERT 前的全部域内规则。
func (n *Node) ValidateForCreate() error {
	if n == nil {
		return errx.New(errx.ErrInvalidInput, "node is nil")
	}
	if n.TenantID == "" {
		return errx.New(errx.ErrInvalidInput, "node.tenant_id 不能为空")
	}
	if n.Name == "" {
		return errx.New(errx.ErrInvalidInput, "node.name 不能为空")
	}
	if len(n.Name) > NodeNameMaxLen {
		return errx.New(errx.ErrInvalidInput, "node.name 超出最大长度").
			WithFields("max", NodeNameMaxLen)
	}
	if n.Status == "" {
		n.Status = NodePending
	}
	if !n.Status.Valid() {
		return errx.New(errx.ErrInvalidInput, "node.status 不合法").
			WithFields("got", string(n.Status))
	}
	return nil
}
