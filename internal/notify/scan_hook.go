package notify

// scan_hook.go —— scan 模块 → notify 模块的桥接（PR-S25）。
//
// scan.TaskNotifier 接口由 scan 包定义，我们在这里提供实现。
// scan 包不直接 import notify，避免层次倒挂；cmd/server wire 时手动装配。

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/notify/domain"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// ScanHook 实现 scan.TaskNotifier。失败仅 log，不阻断 scan 主流程。
type ScanHook struct {
	svc    Service
	logger Logger
}

// NewScanHook 构造桥接器。svc 不可空；logger 可空。
func NewScanHook(svc Service, logger Logger) *ScanHook {
	return &ScanHook{svc: svc, logger: logger}
}

// OnTaskTerminal scan task 进入终态触发。
func (h *ScanHook) OnTaskTerminal(ctx context.Context, t *scandomain.ScanTask) {
	if h == nil || h.svc == nil || t == nil {
		return
	}
	var kind domain.EventKind
	switch t.Status {
	case scandomain.TaskCompleted:
		kind = domain.EventTaskCompleted
	case scandomain.TaskFailed, scandomain.TaskCanceled:
		// canceled 也走 task_failed 通道（用户取消 / sweeper 标 failed 都视作"task 没成"）
		kind = domain.EventTaskFailed
	default:
		return
	}
	pid := t.ProjectID
	ev := Event{
		Kind:      kind,
		TenantID:  t.TenantID,
		ProjectID: &pid,
		Topic:     "scan.task.terminal.v1",
		Payload: map[string]any{
			"task_id":    t.ID,
			"task_name":  t.Name,
			"project_id": t.ProjectID,
			"kind":       string(t.Kind),
			"status":     string(t.Status),
			"target":     t.Target,
		},
	}
	if err := h.svc.Notify(ctx, ev); err != nil && h.logger != nil {
		h.logger.LogError(ctx, "notify.ScanHook: task terminal notify failed", err,
			"task_id", t.ID, "status", string(t.Status))
	}
}

// OnHighSeverityResult 高危 result 上报触发。
func (h *ScanHook) OnHighSeverityResult(ctx context.Context, r *scandomain.ScanResult) {
	if h == nil || h.svc == nil || r == nil {
		return
	}
	// 从 nuclei JSON 提取人类可读字段
	severity, title, host := extractNucleiFields(r.Data)
	pid := r.ProjectID
	ev := Event{
		Kind:      domain.EventFindingHigh,
		TenantID:  r.TenantID,
		ProjectID: &pid,
		Topic:     "scan.result.high_severity.v1",
		Payload: map[string]any{
			"result_id":  r.ID,
			"task_id":    r.TaskID,
			"project_id": r.ProjectID,
			"severity":   severity,
			"title":      title,
			"host":       host,
		},
	}
	if err := h.svc.Notify(ctx, ev); err != nil && h.logger != nil {
		h.logger.LogError(ctx, "notify.ScanHook: finding notify failed", err,
			"result_id", r.ID)
	}
}

func extractNucleiFields(data map[string]any) (severity, title, host string) {
	info, _ := data["info"].(map[string]any)
	if info != nil {
		severity, _ = info["severity"].(string)
		title, _ = info["name"].(string)
	}
	host, _ = data["host"].(string)
	return severity, title, host
}
