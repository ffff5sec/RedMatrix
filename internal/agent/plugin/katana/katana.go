// Package katana 是 web_crawl 任务的真插件（PR-S49；补 SPEC §2.5 URL/路径维度）。
//
// 调用方式：
//
//	katana -u <target> -jsonl -silent -d 2 -c 10
//
// -u <target>：起始 URL / host（katana 自动补 scheme）
// -jsonl：每行一个 JSON 输出（path-only 模式）
// -silent：屏蔽 banner / 进度
// -d 2：爬取深度（默认 2 层；SPEC MVP 不深爬避免预算爆炸）
// -c 10：并发（默认 10；后续 settings 可覆盖）
//
// 与 httpx WebCrawl 的差异：httpx 只探 URL 存活，katana 真爬取页面 + 跟随
// JS 链接 + 表单 / API endpoint 发现。SPEC §2.5 列 katana 为 L2 URL/路径维度
// 首选工具。
//
// dev / CI 没装 katana：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package katana

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

// binaryName katana 可执行文件名；可被测试覆盖。
var binaryName = "katana"

// MaxResults 单任务 URL 结果上限。一个大站爬 2 层可上万链接；MVP 限 1000
// 既覆盖典型用例又防 ReportTaskResults 巨包 stream error。
var MaxResults = 1000

// DefaultDepth 默认爬取深度；settings.depth 可覆盖。
const DefaultDepth = 2

// DefaultConcurrency 默认并发；settings.concurrency 可覆盖。
const DefaultConcurrency = 10

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；katana 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "web_crawl" }

// IsMock 给 Loop 判定是否走 sleep 节奏；真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 支持：
//   - "depth" (float64/int)：爬取深度，缺省 2，上限 5（防失控）
//   - "concurrency" (float64/int)：并发，缺省 10，上限 50
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if targetKind == "" {
		targetKind = "url"
	}
	switch targetKind {
	case "url", "host":
	default:
		return nil, fmt.Errorf("katana: target_kind=%q 不支持（仅 url/host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, fmt.Errorf("katana: %w", err)
	}

	depth := DefaultDepth
	if d, ok := readPositiveInt(settings, "depth"); ok {
		depth = clampInt(d, 1, 5)
	}
	conc := DefaultConcurrency
	if c, ok := readPositiveInt(settings, "concurrency"); ok {
		conc = clampInt(c, 1, 50)
	}

	args := []string{
		"-u", target,
		"-jsonl",
		"-silent",
		"-d", fmt.Sprintf("%d", depth),
		"-c", fmt.Sprintf("%d", conc),
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("katana: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 katana -jsonl 输出。导出供测试用。
//
// katana 输出形态（jsonl）：
//
//	{"timestamp":"2026-05-14T...","request":{"method":"GET","endpoint":"https://x/a"}}
//
// 也可能是更简洁的：
//
//	{"endpoint":"https://x/a","method":"GET","tag":"link"}
//
// 兼容两种：优先取 request.endpoint，回落 endpoint 字段。
func ParseJSONLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry katanaEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		endpoint := strings.TrimSpace(entry.Endpoint)
		if endpoint == "" {
			endpoint = strings.TrimSpace(entry.Request.Endpoint)
		}
		if endpoint == "" {
			continue
		}
		// 同 URL 去重（一次爬取经常返回同链接多次）
		if _, dup := seen[endpoint]; dup {
			continue
		}
		seen[endpoint] = struct{}{}
		method := strings.TrimSpace(entry.Method)
		if method == "" {
			method = strings.TrimSpace(entry.Request.Method)
		}
		row := map[string]any{"url": endpoint}
		if method != "" {
			row["method"] = method
		}
		if entry.Tag != "" {
			row["tag"] = entry.Tag
		}
		if entry.StatusCode > 0 {
			row["status_code"] = entry.StatusCode
		}
		rows = append(rows, row)
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("katana: scan output: %w", err)
	}
	return rows, nil
}

// katanaEntry 兼容两种 katana 输出：扁平字段 / 嵌套 request 字段。
type katanaEntry struct {
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	Tag        string `json:"tag"`
	StatusCode int    `json:"status_code"`
	Request    struct {
		Endpoint string `json:"endpoint"`
		Method   string `json:"method"`
	} `json:"request"`
}

// readPositiveInt 从 settings 取数字字段，支持 float64 / int / json.Number。
// 0 / 负数返 (0, false)。
func readPositiveInt(s map[string]any, key string) (int, bool) {
	if s == nil {
		return 0, false
	}
	switch v := s[key].(type) {
	case float64:
		if v > 0 {
			return int(v), true
		}
	case int:
		if v > 0 {
			return v, true
		}
	case json.Number:
		if i, err := v.Int64(); err == nil && i > 0 {
			return int(i), true
		}
	}
	return 0, false
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
