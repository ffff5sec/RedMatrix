package domain

// AllowedNodes 表示某项目的可用节点配置（LLD 11 §3.4）。
//
// 语义：
//   - AllNodes=true：所有节点可用（与 project_allowed_nodes 表中无该项目记录对应）
//   - AllNodes=false：白名单模式（NodeIDs 是显式列表）
//
// 不变式：AllNodes=true 时 NodeIDs 必须为空；AllNodes=false 时 NodeIDs 可为空
// （表示"暂时禁用所有节点"——任何 IsNodeAllowed 查询返 false）。
type AllowedNodes struct {
	AllNodes bool
	NodeIDs  []string
}

// Contains 判断 nodeID 是否被允许。
func (a AllowedNodes) Contains(nodeID string) bool {
	if a.AllNodes {
		return true
	}
	for _, id := range a.NodeIDs {
		if id == nodeID {
			return true
		}
	}
	return false
}

// IsExplicitWhitelist 是否处于显式白名单模式（!AllNodes）。
func (a AllowedNodes) IsExplicitWhitelist() bool {
	return !a.AllNodes
}
