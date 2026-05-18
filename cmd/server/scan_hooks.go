// scan_hooks.go —— 把 notify + finding 两个钩子合成一个 scan.TaskNotifier。
//
// scan service 只接受单个 TaskNotifier，cmd/server 这里用 composite 模式把多个
// 模块的 hook 串起来。任意 hook 失败仅 log，不阻断 scan 主流程。
package main

import (
	"context"

	assetDomain "github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/finding"
	"github.com/ffff5sec/RedMatrix/internal/notify"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// AssetLookup PR-S70：scan_hook 用来按 (tenant, project, host) 反查 asset 拿
// AssetID 填到 finding。asset.Service 已实现此签名；写成 interface 让 hook
// 不强依赖 asset 包细节。
type AssetLookup interface {
	LookupByHostValue(ctx context.Context, tenantID, projectID, value string) (*assetDomain.Asset, error)
}

// scanCompositeNotifier 同时持有 notify.ScanHook 和 finding 入口；nil 字段忽略。
type scanCompositeNotifier struct {
	notify  *notify.ScanHook
	finding finding.Service
	assets  AssetLookup // PR-S70 可空：nil = 不填 finding.AssetID
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
		// PR-S70：反查 asset 拿到 ID，让 finding 与 asset 直链。
		// lookup 失败仅 log，不阻断 finding 创建（asset 可能还没派生）。
		var assetIDPtr *string
		if c.assets != nil {
			a, lookupErr := c.assets.LookupByHostValue(ctx, r.TenantID, r.ProjectID, host)
			if lookupErr != nil {
				if c.logger != nil {
					c.logger.LogError(ctx, "finding hook: asset lookup failed", lookupErr,
						"tenant", r.TenantID, "project", r.ProjectID, "host", host)
				}
			} else if a != nil {
				id := a.ID
				assetIDPtr = &id
			}
		}
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
			AssetID:     assetIDPtr, // PR-S70
		})
		if err != nil && c.logger != nil {
			c.logger.LogError(ctx, "finding hook: upsert failed", err,
				"result_id", r.ID, "template_id", tmpl, "host", host)
		}
	}
}

// scan.TaskNotifier 编译期断言。
var _ scan.TaskNotifier = (*scanCompositeNotifier)(nil)
