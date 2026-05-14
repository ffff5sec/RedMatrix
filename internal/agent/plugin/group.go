// group.go PR-S56 —— 多 plugin 同 kind 聚合的内部包装类型。
//
// 引入背景：SPEC §2.5 资产发现要求多源覆盖（如子域名 = subfinder + amass +
// crt.sh + fofa 联合用），但 Plugin Registry 当前是 kind→Plugin 1:1，env
// 只能多选一。本文件加 group 类型实现 Plugin interface 内部聚合多 sub-plugin。
//
// 设计：
//   - group 仍实现 plugin.Plugin（外部完全透明）
//   - Run 串行调 sub-plugin（先稳后并行；后续可改 errgroup）
//   - 任一 plugin 错不阻塞其他（最大化结果覆盖率）
//   - 全部 plugin 都错才返复合 error
//   - 结果按 sub-plugin 顺序拼接，下游 chain_extractor / asset.UpsertFromResults
//     已有 dedup，本层不再重复
//   - Kind 返第一个 sub-plugin 的 kind（聚合前提：所有 sub 同 kind）
//   - IsMock 全 sub-plugin 都是 mock 才返 true
package plugin

import (
	"context"
	"errors"
	"fmt"
)

// group 包装多个同 kind 的 sub-plugin。
type group struct {
	plugins []Plugin
}

// newGroup 用现有 plugins 构造 group。空切片或单元素无意义但允许（Registry 不传）。
func newGroup(plugins []Plugin) *group {
	return &group{plugins: plugins}
}

// Kind 返第一个 sub-plugin 的 kind。Registry 仅把同 kind 的 plugin 加进同一
// group，所以任意 sub.Kind() 应一致。空 group 返空字符串（不应发生）。
func (g *group) Kind() string {
	if g == nil || len(g.plugins) == 0 {
		return ""
	}
	return g.plugins[0].Kind()
}

// IsMock 全部 sub-plugin 都是 mock 才返 true。任一真插件 → 走真路径。
func (g *group) IsMock() bool {
	if g == nil || len(g.plugins) == 0 {
		return true
	}
	for _, p := range g.plugins {
		if !p.IsMock() {
			return false
		}
	}
	return true
}

// Run 串行调全部 sub-plugin 聚合结果。
//
// 错误策略：
//   - 任一 plugin 错收集到 errs 列表，不中断其他
//   - 所有 plugin 都错 → 返复合 errors.Join
//   - 至少一个 plugin 成功 → 返合并结果 + nil error（错误丢失？故意，调用方
//     拿到部分结果优于全失败）
//
// 结果合并：
//   - 按 sub-plugin 顺序追加（不排序）
//   - 不去重（下游 asset.UpsertFromResults 用 (tenant,project,kind,value)
//     UNIQUE 兜底；chain_extractor.ExtractTargetsForKind 也 seen-map dedup）
func (g *group) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if g == nil || len(g.plugins) == 0 {
		return nil, errors.New("plugin: group is empty")
	}
	if len(g.plugins) == 1 {
		// 单 plugin 直通；不额外开销
		return g.plugins[0].Run(ctx, target, targetKind, settings)
	}

	merged := make([]map[string]any, 0, 32)
	errs := make([]error, 0, len(g.plugins))
	successCount := 0
	for _, p := range g.plugins {
		rows, err := p.Run(ctx, target, targetKind, settings)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", subPluginName(p), err))
			continue
		}
		successCount++
		merged = append(merged, rows...)
	}
	// 全部失败才返错；部分成功视为整体成功（结果优先于错误信号）
	if successCount == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("plugin: all %d sub-plugins failed: %w", len(g.plugins), errors.Join(errs...))
	}
	return merged, nil
}

// subPluginName 推断 sub-plugin 标识用于错误消息。Plugin interface 无 Name()
// 方法；用 kind + IsMock 状态合成。重名时 caller 看堆栈区分。
func subPluginName(p Plugin) string {
	if p == nil {
		return "<nil>"
	}
	if p.IsMock() {
		return p.Kind() + "(mock)"
	}
	return p.Kind()
}

// asGroup 把 Plugin 转成 group（若已是）；否则返 nil。仅供 Registry 内部用。
// 返 nil 让 caller 用 newGroup 包装。
func asGroup(p Plugin) *group {
	if g, ok := p.(*group); ok {
		return g
	}
	return nil
}
