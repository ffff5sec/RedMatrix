// Package audithook 是跨模块共享的审计钩子接口（PR-S35）。
//
// 上游 handler（identity / scan / finding / pluginpkg / ...）接受 Hook
// 写审计，避免直接依赖 audit 包。cmd/server 在装配时用 audit.Service 适配
// 出 Hook 注入。
//
// 使用模式：
//
//	type Handler struct {
//	    svc   ...
//	    audit audithook.Hook // 可空；nil 时 fire-and-forget
//	}
//	func (h *Handler) WithAudit(a audithook.Hook) *Handler { h.audit = a; return h }
//	func (h *Handler) X(...) {
//	    ...
//	    if h.audit != nil {
//	        _ = h.audit.Log(ctx, audithook.Event{Action: "x_done", ...})
//	    }
//	}
package audithook

import "context"

// Event 通用审计事件 payload；与 audit.LogEvent 字段同形。
type Event struct {
	Action        string
	ResourceKind  string
	ResourceID    string
	TenantID      string
	ProjectID     string
	ActorUserID   string
	ActorUsername string
	ActorIP       string
	UserAgent     string
	Payload       map[string]any
}

// Hook 审计写入接口；nil = 无审计。
type Hook interface {
	Log(ctx context.Context, ev Event) error
}

// NoopHook 永远成功；用作测试或可关 audit 的场景。
type NoopHook struct{}

// Log 实现 Hook；忽略 event 返 nil。
func (NoopHook) Log(_ context.Context, _ Event) error { return nil }
