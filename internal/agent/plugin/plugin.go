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
type Registry struct {
	plugins map[string]Plugin
}

// NewRegistry 空 Registry。
func NewRegistry() *Registry {
	return &Registry{plugins: make(map[string]Plugin)}
}

// Register 注册（同 kind 重复注册后写覆盖前）。
func (r *Registry) Register(p Plugin) {
	if r == nil || p == nil {
		return
	}
	r.plugins[p.Kind()] = p
}

// Get 取插件；不存在返 nil。
func (r *Registry) Get(kind string) Plugin {
	if r == nil {
		return nil
	}
	return r.plugins[kind]
}
