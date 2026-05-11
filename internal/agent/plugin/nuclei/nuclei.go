// Package nuclei 是 vuln_scan 任务的真插件（PR-S21）。
//
// 调用方式：
//
//	nuclei -u <target> -jsonl -silent -severity <levels> -no-color
//
// -u <target>：目标 URL / host / IP
// -jsonl：JSON Lines 输出
// -silent：抑制 banner 和进度
// -severity：限制扫描的严重程度，避免低优先级嘈杂结果
// -no-color：去 ANSI 色码（agent 日志干净）
//
// 输出按一行一发现 → []map[string]any
//
//	{
//	  "template_id": "CVE-2023-xxxx",
//	  "severity":    "high",
//	  "name":        "Foo SQL injection",
//	  "description": "...",
//	  "host":        "https://example.com",
//	  "matched_at":  "https://example.com/api/...",
//	  "type":        "http"
//	}
//
// nuclei 不在 PATH 时 New 返 ErrNotInstalled，cmd/node 静默回落 mock。
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// binaryName 可被测试覆盖。
var binaryName = "nuclei"

// DefaultSeverity 默认扫的严重等级（去除 info / unknown，减噪音）。
const DefaultSeverity = "low,medium,high,critical"

// MaxResults 单 task 漏洞结果上限——nuclei 偶发万级结果（错配模板），cap 防巨包 RPC。
const MaxResults = 500

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "vuln_scan" }

// IsMock 真插件 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 可携：
//   - severity string："critical" / "high,critical" 等
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if targetKind == "cidr" {
		return nil, fmt.Errorf("nuclei: target_kind=cidr 不支持（先用 nmap 摸活机再 vuln_scan）")
	}
	// nuclei 接 host/ip/url；safetarget 校选项注入 / shell meta
	tk := targetKind
	if tk == "" {
		tk = "host"
	}
	if err := safetarget.ValidateTarget(target, tk); err != nil {
		return nil, fmt.Errorf("nuclei: %w", err)
	}

	severity := DefaultSeverity
	if settings != nil {
		if v, ok := settings["severity"].(string); ok && strings.TrimSpace(v) != "" {
			severity = strings.TrimSpace(v)
		}
	}
	// severity 简单校（防 -h / shell meta）
	if !validSeverityList(severity) {
		return nil, fmt.Errorf("nuclei: severity 不合法 (got=%q)", severity)
	}

	args := []string{
		"-u", target,
		"-jsonl",
		"-silent",
		"-no-color",
		"-severity", severity,
		// 速率与超时控制
		"-rate-limit", "150",
		"-timeout", "10",
		"--",
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// nuclei 在无命中时 exit 0；扫描错（target 不可达 / 模板加载错）exit !=0
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nuclei: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 nuclei -jsonl 输出（NDJSON）。导出供测试。
//
// nuclei 一行 JSON 结构（v3）：
//
//	{
//	  "template-id":   "...",
//	  "info": {"name":"...", "severity":"...", "description":"..."},
//	  "host":           "https://...",
//	  "matched-at":     "https://.../path",
//	  "type":           "http"
//	}
//
// 容错：单行 JSON 错跳过；空行跳过；达 MaxResults 截断。
func ParseJSONLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 8)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry nucleiEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // 跳过坏行不让一行毁全局
		}
		row := convertRow(&entry)
		if row == nil {
			continue
		}
		rows = append(rows, row)
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("nuclei: scan output: %w", err)
	}
	return rows, nil
}

func convertRow(e *nucleiEntry) map[string]any {
	id := strings.TrimSpace(e.TemplateID)
	if id == "" {
		return nil
	}
	row := map[string]any{
		"template_id": id,
		"severity":    strings.ToLower(strings.TrimSpace(e.Info.Severity)),
	}
	if e.Info.Name != "" {
		row["name"] = e.Info.Name
	}
	if e.Info.Description != "" {
		row["description"] = e.Info.Description
	}
	if e.Host != "" {
		row["host"] = e.Host
	}
	if e.MatchedAt != "" {
		row["matched_at"] = e.MatchedAt
	}
	if e.Type != "" {
		row["type"] = e.Type
	}
	return row
}

// validSeverityList 校 "high,critical" 形态：每项 ∈ {info,low,medium,high,critical,unknown}。
func validSeverityList(s string) bool {
	allowed := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true,
		"critical": true, "unknown": true,
	}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" || !allowed[p] {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// === nuclei -jsonl 单行解码结构（v3，仅取所需字段） ===

type nucleiEntry struct {
	TemplateID string     `json:"template-id"`
	Info       nucleiInfo `json:"info"`
	Host       string     `json:"host"`
	MatchedAt  string     `json:"matched-at"`
	Type       string     `json:"type"`
	// 其它字段（curl-command / extracted-results / request 等）暂不取，scan_results.data
	// schema-less 后续扩 ParseJSONLines 即可不破前向。
}

type nucleiInfo struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}
