// Package gospider 是 web_crawl 任务的第三个真插件（PR-S52；补 SPEC §2.5
// URL/路径维度的爬虫多源覆盖）。
//
// 调用方式：
//
//	gospider -s <target> --json --no-redirect -d 2 -c 10
//
// -s：起始 URL
// --json：每行一个 JSON 输出
// --no-redirect：不跟 30x（防被钓到外站）
// -d：深度（缺省 2；settings.depth 覆盖）
// -c：并发（缺省 10；settings.concurrency 覆盖）
//
// 与 katana 的差异：
//   - katana：DOM + JS 解析能力更强，对 SPA 友好；输出已规范化
//   - gospider：sitemap / robots.txt / common JS 库自动探，输出含 source 字段
//     便于追溯
//
// 两者并存满足"主动爬覆盖率 ≥ 主流工具组合"。本插件走 web_crawl kind；
// cmd/node 通过 WEB_CRAWL_PLUGIN env 多选一。
//
// dev / CI 没装 gospider：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package gospider

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

// binaryName gospider 可执行文件名；可被测试覆盖。
var binaryName = "gospider"

// MaxResults 单任务结果上限；大站 2 层爬可上万链接，限 1000（与 katana 同）。
var MaxResults = 1000

// DefaultDepth 爬深度；settings.depth 可覆盖（1-5）。
const DefaultDepth = 2

// DefaultConcurrency 并发；settings.concurrency 可覆盖（1-50）。
const DefaultConcurrency = 10

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；gospider 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "web_crawl" }

// IsMock 真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 支持：
//   - "depth" (float64/int)：1-5
//   - "concurrency" (float64/int)：1-50
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
		return nil, fmt.Errorf("gospider: target_kind=%q 不支持（仅 url/host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, fmt.Errorf("gospider: %w", err)
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
		"-s", target,
		"--json",
		"--no-redirect",
		"-d", fmt.Sprintf("%d", depth),
		"-c", fmt.Sprintf("%d", conc),
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gospider: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 gospider --json 输出。导出供测试用。
//
// gospider JSON 行形态：
//
//	{"output_type":"href","input":"https://x","source":"body",
//	 "output":"https://x/a","status":"200","length":1234}
//
// output_type 可能值：href / form / linkfinder / sitemap / robots / subdomain。
// 提取 output 作 URL；保留 source / status / length 元数据；去重。
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
		var entry gospiderEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		out := strings.TrimSpace(entry.Output)
		if out == "" {
			continue
		}
		if _, dup := seen[out]; dup {
			continue
		}
		seen[out] = struct{}{}
		row := map[string]any{"url": out}
		if entry.OutputType != "" {
			row["tag"] = entry.OutputType
		}
		if entry.Source != "" {
			row["source"] = entry.Source
		}
		if entry.Status != "" {
			row["status_code"] = entry.Status
		}
		if entry.Length > 0 {
			row["length"] = entry.Length
		}
		rows = append(rows, row)
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("gospider: scan output: %w", err)
	}
	return rows, nil
}

// gospiderEntry gospider --json 单行结构（仅声明用得到的字段）。
type gospiderEntry struct {
	OutputType string `json:"output_type"`
	Input      string `json:"input"`
	Source     string `json:"source"`
	Output     string `json:"output"`
	Status     string `json:"status"`
	Length     int    `json:"length"`
}

// readPositiveInt 从 settings 取数字字段（支持 float64 / int / json.Number）。
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
