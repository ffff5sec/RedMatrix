// Package subfinder 是 subdomain 任务的真插件（PR-S10）。
//
// 调用方式：
//
//	subfinder -d <target> -silent -oJ
//
// -d <target>：根域
// -silent：不输出 banner / 进度（让 stdout 干净）
// -oJ：JSON Lines 输出，每行 {"host":"...","input":"...","source":"..."}
//
// 输出按一行一域名 → []map[string]any{{"name": "...", "source": "..."}}。
//
// dev / CI 没装 subfinder：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package subfinder

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

// binaryName subfinder 可执行文件名；可被测试覆盖。
var binaryName = "subfinder"

// MaxSubdomains 单任务子域结果上限。被动枚举对 example.com 可返 22k+ 行；
// 真实业务域通常 <500，这里限到 500 既覆盖典型用例又防 ReportTaskResults
// 巨包 stream error。可被测试覆盖。
var MaxSubdomains = 500

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；subfinder 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "subdomain" }

// IsMock 给 Loop 判定是否走 sleep 节奏；真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 当前未读（subfinder 默认 sources 已够 MVP；后续可加 -sources 白名单）。
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
		return nil, fmt.Errorf("subfinder: empty target")
	}
	// 被动子域枚举只对域名有意义；ip/cidr/url 都不合适
	if targetKind != "" && targetKind != "host" {
		return nil, fmt.Errorf("subfinder: target_kind=%q 不支持（仅 host）", targetKind)
	}

	args := []string{"-d", target, "-silent", "-oJ"}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("subfinder: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 subfinder -oJ 输出（NDJSON）。导出供测试用。
//
// 容错：单行 JSON 错跳过；空行跳过。整体非空但全错时返空切片，无 error。
func ParseJSONLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 域名行可能较长但不会上 MB
	rows := make([]map[string]any, 0, 16)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry struct {
			Host   string `json:"host"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // 跳过坏行；不让一行毁全局
		}
		host := strings.TrimSpace(entry.Host)
		if host == "" {
			continue
		}
		row := map[string]any{"name": strings.ToLower(host)}
		if entry.Source != "" {
			row["source"] = entry.Source
		}
		rows = append(rows, row)
		if len(rows) >= MaxSubdomains {
			break // 达上限，剩下的 source 就丢弃
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("subfinder: scan output: %w", err)
	}
	return rows, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
