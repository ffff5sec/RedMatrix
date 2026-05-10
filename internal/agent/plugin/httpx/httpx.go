// Package httpx 是 fingerprint / web_crawl 任务的真插件（PR-S11）。
//
// 调用方式：
//
//	httpx -u <target> -json -silent -title -status-code [-td -tech-detect]
//
// -u <target>：单目标输入（host / url / ip 均可；httpx 自己探 80/443）
// -json：每行一条 JSON
// -silent：抑制 banner / 进度
// -title -status-code：基础 HTTP 元数据
// -td -tech-detect：技术栈识别（仅 fingerprint 路径开启，省 web_crawl 路径开销）
//
// 同一 binary 包两个 Plugin wrapper：
//   - NewFingerprint() → kind="fingerprint"，输出 {target, tech, status, title, webserver}
//   - NewWebCrawl()    → kind="web_crawl"，  输出 {url, status, title}
//
// target_kind:
//   - host / ip / url：直接传 httpx
//   - cidr：拒（httpx 不针对 CIDR；CIDR 走 nmap）
//
// dev / CI 没装 httpx：New* 返 ErrNotInstalled，cmd/node 自动回落 mock。
package httpx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
)

// binaryName httpx 可执行文件名；可被测试覆盖。
var binaryName = "httpx"

// Plugin httpx 插件。kind 决定输出 schema + 是否开 -td 探测。
type Plugin struct {
	bin  string
	kind string // "fingerprint" / "web_crawl"
}

// NewFingerprint 构造 fingerprint kind 插件；二进制不在 PATH 返 ErrNotInstalled。
func NewFingerprint() (*Plugin, error) { return newPlugin("fingerprint") }

// NewWebCrawl 构造 web_crawl kind 插件；二进制不在 PATH 返 ErrNotInstalled。
func NewWebCrawl() (*Plugin, error) { return newPlugin("web_crawl") }

func newPlugin(kind string) (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin, kind: kind}, nil
}

// Kind 实现 Plugin。
func (p *Plugin) Kind() string {
	if p == nil {
		return ""
	}
	return p.kind
}

// IsMock 真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	_ map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("httpx: empty target")
	}
	if targetKind == "cidr" {
		return nil, fmt.Errorf("httpx: target_kind=cidr 不支持（用 nmap 跑 port_scan）")
	}

	args := []string{
		"-u", target,
		"-json",
		"-silent",
		"-title",
		"-status-code",
		"-no-color",
	}
	if p.kind == "fingerprint" {
		args = append(args, "-td", "-tech-detect")
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("httpx: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return parseJSONLines(stdout.Bytes(), p.kind)
}

// ParseJSONLinesFingerprint / ParseJSONLinesWebCrawl 导出供测试用。
func ParseJSONLinesFingerprint(out []byte) ([]map[string]any, error) {
	return parseJSONLines(out, "fingerprint")
}

// ParseJSONLinesWebCrawl 同上。
func ParseJSONLinesWebCrawl(out []byte) ([]map[string]any, error) {
	return parseJSONLines(out, "web_crawl")
}

// parseJSONLines 解 httpx -json 输出（NDJSON）。
//
// 容错：单行 JSON 错跳过；空行跳过。整体非空但全错时返空切片，无 error。
func parseJSONLines(out []byte, kind string) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 4)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry httpxEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		row := convertRow(&entry, kind)
		if row == nil {
			continue
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("httpx: scan output: %w", err)
	}
	return rows, nil
}

// convertRow 把 httpx 一行 entry 按 kind 转 plugin 输出 schema。
//
// fingerprint: {target, tech, status, title, webserver}
// web_crawl:   {url, status, title}
func convertRow(e *httpxEntry, kind string) map[string]any {
	url := strings.TrimSpace(e.URL)
	if url == "" && strings.TrimSpace(e.Input) != "" {
		// 极端情况：httpx 可能未给 url 但给 input
		url = e.Input
	}
	if url == "" {
		return nil
	}
	switch kind {
	case "fingerprint":
		row := map[string]any{
			"target": url,
		}
		if e.StatusCode != 0 {
			row["status"] = e.StatusCode
		}
		if e.Title != "" {
			row["title"] = e.Title
		}
		if e.Webserver != "" {
			row["webserver"] = e.Webserver
		}
		if len(e.Technologies) > 0 {
			row["tech"] = e.Technologies
		}
		return row
	case "web_crawl":
		row := map[string]any{
			"url": url,
		}
		if e.StatusCode != 0 {
			row["status"] = e.StatusCode
		}
		if e.Title != "" {
			row["title"] = e.Title
		}
		return row
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// httpxEntry httpx -json 单行解码结构（仅取需要字段）。
type httpxEntry struct {
	URL          string   `json:"url"`
	Input        string   `json:"input"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	Webserver    string   `json:"webserver"`
	Technologies []string `json:"tech"`
}
