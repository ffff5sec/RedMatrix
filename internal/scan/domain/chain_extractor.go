package domain

// chain_extractor.go —— 套件 kind 间数据流提取器（PR-S27）。
//
// 链顺序 = suite.Kinds[] 数组顺序。当某 step 的 task 全部 terminal 时，
// service 调 ExtractTargetsForKind 拿该 step 全部 results → 提取出下一 step 的 targets。
//
// 每个 source kind 对应一个提取规则：
//   - subdomain (subfinder):     result.data.host           → 下游 targets
//   - fingerprint (httpx):       result.data.url (live)     → 下游 targets
//   - port_scan / web_crawl / vuln_scan: 不导出（链终止）
//
// 输入 targets 顺序保序去重；空结果 → 链终止 + run.failed。

import (
	"net/url"
	"strings"
)

// ExtractTargetsForKind 从 source kind 的 results 中抽取下一 step 的 targets。
//
// 不识别的 kind → 返回 nil（视作终端 kind，链结束）。
// data 结构假定与 agent 上报的 nuclei/httpx/subfinder 输出对齐。
func ExtractTargetsForKind(sourceKind TaskKind, results []ResultData) []string {
	switch sourceKind {
	case KindSubdomain:
		return extractSubdomainHosts(results)
	case KindFingerprint:
		return extractFingerprintURLs(results)
	}
	return nil
}

// ResultData scan_results.data 的最小快照接口；调用方传 []map[string]any。
type ResultData = map[string]any

// extractSubdomainHosts subfinder 输出：每行一个 result，data.host = "sub.example.com"。
func extractSubdomainHosts(results []ResultData) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, r := range results {
		host, _ := r["host"].(string)
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// extractFingerprintURLs httpx 输出：data.url (live) + data.status_code。
// 仅取 live 的 URL（2xx/3xx）；4xx/5xx/无 status 跳过。
// 返回的 URL host 部分（避免下游接收完整 URL 把 path 也带进去），但保留 scheme/port。
func extractFingerprintURLs(results []ResultData) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, r := range results {
		raw, _ := r["url"].(string)
		raw = strings.TrimSpace(raw)
		if raw == "" {
			// 退化：仅有 host 字段也接受（兼容旧 httpx 输出）
			if h, _ := r["host"].(string); h != "" {
				raw = h
			} else {
				continue
			}
		}
		// 校验 live：status_code 缺失或 ≥ 200 < 400
		switch v := r["status_code"].(type) {
		case float64:
			if int(v) >= 400 {
				continue
			}
		case int:
			if v >= 400 {
				continue
			}
		}
		// 规范化：保留 scheme + host + 可选 port，去 path/query
		normalized := normalizeURLForChaining(raw)
		if normalized == "" {
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

// normalizeURLForChaining 规范化 URL：保留 scheme://host[:port]，去 path/query/fragment。
// 不带 scheme 的字符串当作 host 透传。
func normalizeURLForChaining(raw string) string {
	if !strings.Contains(raw, "://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
