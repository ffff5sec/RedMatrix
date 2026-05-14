// Package wayback 是 web_crawl 任务的第四个真插件（PR-S52；补 SPEC §2.5
// URL/路径维度的被动归档源）。
//
// 调用方式：
//
//	echo <target> | waybackurls
//
// waybackurls（tomnomnom）从 Wayback Machine / Common Crawl 等历史归档拉
// 该 host 全部历史 URL；纯被动，不发出新流量，stealth 友好。
//
// 与 katana / gospider 的差异：
//   - katana / gospider：主动爬，发出 HTTP 请求；速度受站点限速；只能拿
//     当下可见的 URL
//   - wayback：被动归档，能挖出"以前发过但现在已下线"的隐藏端点（管理后台 /
//     调试接口 / 内部 API）；红队场景独特价值
//
// 本插件走 web_crawl kind；cmd/node 通过 WEB_CRAWL_PLUGIN env 多选一。
//
// dev / CI 没装 waybackurls：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package wayback

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// binaryName waybackurls 可执行文件名；可被测试覆盖。
var binaryName = "waybackurls"

// MaxResults 单任务结果上限。归一站 wayback 可返数万行；限 2000 在覆盖率
// 与 ReportTaskResults stream error 之间折中。
var MaxResults = 2000

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；waybackurls 不在 PATH 时返 ErrNotInstalled。
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
// settings 不读（waybackurls CLI 几乎没参数；MVP 不暴露 -dates / -no-subs）。
// target 形态：host / url。url 形态时取 host 部分（waybackurls 只接 bare host）。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	_ map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if targetKind == "" {
		targetKind = "host"
	}
	switch targetKind {
	case "host":
		if err := safetarget.ValidateTarget(target, "host"); err != nil {
			return nil, fmt.Errorf("wayback: %w", err)
		}
	case "url":
		if err := safetarget.ValidateTarget(target, "url"); err != nil {
			return nil, fmt.Errorf("wayback: %w", err)
		}
		// 提取 host 部分给 waybackurls
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("wayback: 无法从 url 提取 host: %s", target)
		}
		target = u.Hostname()
	default:
		return nil, fmt.Errorf("wayback: target_kind=%q 不支持（仅 host/url）", targetKind)
	}

	cmd := exec.CommandContext(ctx, p.bin)
	cmd.Stdin = strings.NewReader(target + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("wayback: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseLines(stdout.Bytes())
}

// ParseLines 解 waybackurls 输出（每行一个 URL）。导出供测试用。
//
// 容错：
//   - 空行跳过
//   - 非 http(s)://... 形态行跳过（防意外 banner / stderr 混入）
//   - 同 URL 去重
//   - 超 MaxResults 截断
func ParseLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// 仅接受 http:// 或 https:// 开头
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		// url.Parse 进一步校：拒非法字符 / 缺 host
		u, err := url.Parse(line)
		if err != nil || u.Host == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		rows = append(rows, map[string]any{
			"url":    line,
			"source": "wayback",
		})
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("wayback: scan output: %w", err)
	}
	return rows, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
