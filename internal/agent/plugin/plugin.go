// Package plugin 是 Agent 任务执行插件抽象（PR-S9）。
//
// Plugin 把"任务 kind → 一组结果"的执行细节从 Loop 中解耦：
//
//	Loop 拉到 AssignedTask → Registry.Get(kind).Run(...) → []map[string]any
//	→ ReportTaskResults
//
// 设计：
//   - 每个 kind（port_scan / web_crawl / subdomain / fingerprint）注册一个 Plugin
//   - 真工具插件（nmap / subfinder / httpx）作为各自子包；这里只定 Plugin 接口
//   - Registry + Mock 实现
//   - 工具二进制不存在时构造函数返 ErrNotInstalled；caller（cmd/node）静默
//     回落到 Mock，让 dev / CI 路径仍可用
package plugin

import (
	"context"
	"errors"
)

// Plugin 任务执行插件。一个 Plugin 只服务一个 task.kind。
type Plugin interface {
	// Kind 返回该插件服务的任务类型（与 scan_tasks.kind 一致）。
	Kind() string

	// IsMock 是否 mock 插件。tasks.Loop 用此走 sleep 节奏（mock 跑得快需限流），
	// group 用此判断聚合粒度。所有现有真插件 + mock 已实现此方法（PR-S56 起
	// 提升到 interface level）。
	IsMock() bool

	// Run 执行扫描；返若干"结果行"（schema-less map，与 ReportTaskResults
	// items 字段同形）。
	//
	// 入参 settings 是 task.settings JSON 直传；插件按需读取（如 nmap 的
	// ports 范围 / -T 速率）。
	Run(ctx context.Context, target, targetKind string, settings map[string]any) ([]map[string]any, error)
}

// ErrNotInstalled 插件依赖的工具二进制不存在；caller 应静默回落 Mock。
var ErrNotInstalled = errors.New("plugin: required tool binary not installed")

// Registry kind → Plugin 路由表。线程安全（仅启动期写）。
//
// PR-S56：同 kind 多次注册时自动包成 group 聚合（SPEC §2.5 多源覆盖）；
// 外部接口（Get / Plugin interface）完全不变。
type Registry struct {
	plugins map[string]Plugin
}

// NewRegistry 空 Registry。
func NewRegistry() *Registry {
	return &Registry{plugins: make(map[string]Plugin)}
}

// Register 注册 plugin。同 kind 已有时自动聚合到 group（PR-S56）：
//   - 首次 Register：单 plugin 直存
//   - 第二次 Register：把已有 + 新的包成 *group
//   - 第 N 次 Register：append 到现有 group
func (r *Registry) Register(p Plugin) {
	if r == nil || p == nil {
		return
	}
	kind := p.Kind()
	existing, has := r.plugins[kind]
	if !has {
		r.plugins[kind] = p
		return
	}
	// 已有：检查是否已是 group
	if g := asGroup(existing); g != nil {
		g.plugins = append(g.plugins, p)
		return
	}
	// 首次冲突：包 group
	r.plugins[kind] = newGroup([]Plugin{existing, p})
}

// Get 取插件；不存在返 nil。可能返单个 plugin 或 *group（均实现 Plugin interface）。
func (r *Registry) Get(kind string) Plugin {
	if r == nil {
		return nil
	}
	return r.plugins[kind]
}

// GetAll 返某 kind 下底层全部 plugins（解包 group 若存在）。
// 测试 / 调试 / 监控用；运行时仍用 Get。
func (r *Registry) GetAll(kind string) []Plugin {
	if r == nil {
		return nil
	}
	p, ok := r.plugins[kind]
	if !ok {
		return nil
	}
	if g := asGroup(p); g != nil {
		out := make([]Plugin, len(g.plugins))
		copy(out, g.plugins)
		return out
	}
	return []Plugin{p}
}
