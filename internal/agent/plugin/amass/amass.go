// Package amass 是 subdomain 任务的真插件（PR-S49；补 SPEC §2.5 子域名多源覆盖）。
//
// 调用方式：
//
//	amass enum -d <target> -json - -silent -timeout 5
//
// enum：子域名枚举子命令
// -d <target>：根域
// -json -：JSON 输出到 stdout（每行一条）
// -silent：屏蔽 banner / 进度
// -timeout 5：分钟级超时上限（默认无限，MVP 限 5min 避免长尾）
//
// 与 subfinder 的差异：amass 更激进（含暴力枚举 + DNS 推导），结果更全但慢；
// subfinder 走被动情报源（更快更轻）。两者并存满足 SPEC §5.1 验收条目
// "子域名发现量 ≥ 主流开源组合 90%"。本 plugin 走 subdomain kind，与
// subfinder 同 kind；cmd/node 通过 SUBDOMAIN_PLUGIN env 二选一。
//
// dev / CI 没装 amass：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package amass

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

// binaryName amass 可执行文件名；可被测试覆盖。
var binaryName = "amass"

// MaxSubdomains 单任务子域结果上限；amass 主动枚举对大域可上万行，
// 限 500 防 ReportTaskResults 巨包 stream error（与 subfinder 同界）。
var MaxSubdomains = 500

// DefaultTimeoutMinutes amass 全流程超时（min）。
const DefaultTimeoutMinutes = 5

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；amass 不在 PATH 时返 ErrNotInstalled。
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
// settings 支持：
//   - "timeout_minutes" (float64/int)：覆盖默认 5min，上限 30min。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if targetKind != "" && targetKind != "host" {
		return nil, fmt.Errorf("amass: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("amass: %w", err)
	}

	timeoutMin := DefaultTimeoutMinutes
	if t, ok := readPositiveInt(settings, "timeout_minutes"); ok {
		if t > 30 {
			t = 30
		}
		timeoutMin = t
	}

	args := []string{
		"enum",
		"-d", target,
		"-json", "-",
		"-silent",
		"-timeout", fmt.Sprintf("%d", timeoutMin),
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("amass: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 amass enum -json - 输出。导出供测试用。
//
// amass JSON 输出形态（v3.x / v4.x 兼容）：
//
//	{"name":"sub.example.com","domain":"example.com","addresses":[{"ip":"1.2.3.4","cidr":"1.0.0.0/8"}],"tag":"cert","sources":["crtsh"]}
//
// 提取：name / domain / sources（取第一个）。addresses 不入资产视图，
// 留给 chain extractor 下游 port_scan/fingerprint 自己解析。
//
// 容错：单行 JSON 错跳过；空 name 跳过；小写归一。
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
		var entry amassEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name))
		if name == "" {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		row := map[string]any{"name": name}
		if len(entry.Sources) > 0 {
			row["source"] = entry.Sources[0]
		}
		rows = append(rows, row)
		if len(rows) >= MaxSubdomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("amass: scan output: %w", err)
	}
	return rows, nil
}

// amassEntry amass -json 单行结构（仅声明用得到的字段）。
type amassEntry struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

// readPositiveInt 从 settings 取数字字段。
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
