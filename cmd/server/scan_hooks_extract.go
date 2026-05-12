// scan_hooks_extract.go —— nuclei result.data JSON 字段抽取。
//
// 与 internal/notify/scan_hook.go 的 extractNucleiFields 行为对齐；这里
// 给 finding 路径再加 template_id / description / reference 抽取。
package main

import (
	"strings"

	findingdomain "github.com/ffff5sec/RedMatrix/internal/finding/domain"
)

func extractNucleiInfo(data map[string]any) (severity, title, host string) {
	info, _ := data["info"].(map[string]any)
	if info != nil {
		severity, _ = info["severity"].(string)
		title, _ = info["name"].(string)
	}
	host, _ = data["host"].(string)
	return severity, title, host
}

// extractTemplateID 优先 data.templateID / template-id；fallback info.classification.cve-id / templateURL basename。
func extractTemplateID(data map[string]any) string {
	for _, key := range []string{"templateID", "template-id", "template_id"} {
		if v, ok := data[key].(string); ok && v != "" {
			return v
		}
	}
	info, _ := data["info"].(map[string]any)
	if info != nil {
		if cls, ok := info["classification"].(map[string]any); ok {
			if cve, ok := cls["cve-id"].(string); ok && cve != "" {
				return cve
			}
		}
	}
	// templateURL 末段
	if v, ok := data["templateURL"].(string); ok && v != "" {
		if i := strings.LastIndexByte(v, '/'); i >= 0 && i+1 < len(v) {
			return strings.TrimSuffix(v[i+1:], ".yaml")
		}
	}
	return ""
}

func extractDescription(data map[string]any) string {
	info, _ := data["info"].(map[string]any)
	if info == nil {
		return ""
	}
	if d, ok := info["description"].(string); ok {
		return d
	}
	return ""
}

func extractReference(data map[string]any) string {
	info, _ := data["info"].(map[string]any)
	if info == nil {
		return ""
	}
	switch v := info["reference"].(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

func findingSeverityFromString(s string) findingdomain.Severity {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return findingdomain.Severity(s)
	}
	return findingdomain.SeverityHigh // fallback：scan 钩子触发条件是 high/critical
}
