// scan_hooks.go —— 把 notify + finding 两个钩子合成一个 scan.TaskNotifier。
//
// scan service 只接受单个 TaskNotifier，cmd/server 这里用 composite 模式把多个
// 模块的 hook 串起来。任意 hook 失败仅 log，不阻断 scan 主流程。
package main

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/finding"
	"github.com/ffff5sec/RedMatrix/internal/notify"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// scanCompositeNotifier 同时持有 notify.ScanHook 和 finding 入口；nil 字段忽略。
type scanCompositeNotifier struct {
	notify  *notify.ScanHook
	finding finding.Service
	logger  *log.Logger
}

func (c *scanCompositeNotifier) OnTaskTerminal(ctx context.Context, t *scandomain.ScanTask) {
	if c.notify != nil {
		c.notify.OnTaskTerminal(ctx, t)
	}
}

func (c *scanCompositeNotifier) OnHighSeverityResult(ctx context.Context, r *scandomain.ScanResult) {
	// 1) 通知投递
	if c.notify != nil {
		c.notify.OnHighSeverityResult(ctx, r)
	}
	// 2) finding 自动创建 / occurrence 累加
	if c.finding != nil {
		sev, title, host := extractNucleiInfo(r.Data)
		ref := extractReference(r.Data)
		desc := extractDescription(r.Data)
		tmpl := extractTemplateID(r.Data)
		if tmpl == "" || host == "" {
			if c.logger != nil {
				c.logger.LogError(ctx, "finding hook: missing template_id / host", nil,
					"result_id", r.ID, "task_id", r.TaskID)
			}
			return
		}
		resultID := r.ID
		_, _, err := c.finding.UpsertFromResult(ctx, finding.UpsertFromResultRequest{
			TenantID:    r.TenantID,
			ProjectID:   r.ProjectID,
			TemplateID:  tmpl,
			Host:        host,
			Severity:    findingSeverityFromString(sev),
			Title:       title,
			Description: desc,
			Reference:   ref,
			ResultID:    &resultID,
		})
		if err != nil && c.logger != nil {
			c.logger.LogError(ctx, "finding hook: upsert failed", err,
				"result_id", r.ID, "template_id", tmpl, "host", host)
		}
	}
}

// scan.TaskNotifier 编译期断言。
var _ scan.TaskNotifier = (*scanCompositeNotifier)(nil)
