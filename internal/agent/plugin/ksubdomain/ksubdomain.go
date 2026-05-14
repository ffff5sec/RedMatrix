// Package ksubdomain 是 subdomain 任务的真插件（PR-S50；补 SPEC §2.5 子域名
// 高速字典爆破维度）。
//
// 调用方式：
//
//	ksubdomain enum -d <target> --silent [-b <bandwidth>]
//
// enum：字典爆破子命令（也支持 verify 子命令做 DNS 验证；本插件只用 enum）
// -d <target>：根域
// --silent：屏蔽 banner / 进度，stdout 只剩"一行一子域名"
// -b：带宽限制，缺省 ksubdomain 自适应；通过 settings.bandwidth_mbps 覆盖
//
// 与 subfinder / amass 的差异：
//   - subfinder：被动情报源聚合（CT 日志 / 第三方 API），快、轻、覆盖低
//   - amass：被动情报 + 主动枚举 + DNS 推导，重、慢、覆盖中
//   - ksubdomain：纯主动字典爆破（SYN 直发 DNS 包），极快（30 万 PPS+），
//     覆盖率取决于字典；适合"已知中型域 + 自有字典"场景
//
// 三者并存满足 SPEC §5.1 验收"子域名发现量 ≥ 主流开源组合 90%"。
// 本插件走 subdomain kind；cmd/node 通过 SUBDOMAIN_PLUGIN env 三选一。
//
// dev / CI 没装 ksubdomain：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package ksubdomain

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// binaryName ksubdomain 可执行文件名；可被测试覆盖。
var binaryName = "ksubdomain"

// MaxSubdomains 单任务子域结果上限（与 subfinder / amass 同界）。
var MaxSubdomains = 500

// hostRe 行内只接受 RFC 1123 合法域名；防 ksubdomain 输出混入 banner 残留。
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；ksubdomain 不在 PATH 时返 ErrNotInstalled。
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
//   - "bandwidth_mbps" (float64/int)：带宽上限 Mbps，缺省 ksubdomain 自适应；
//     1-1000 范围，超界 clamp。
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
		return nil, fmt.Errorf("ksubdomain: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("ksubdomain: %w", err)
	}

	args := []string{"enum", "-d", target, "--silent"}
	if bw, ok := readPositiveInt(settings, "bandwidth_mbps"); ok {
		if bw < 1 {
			bw = 1
		}
		if bw > 1000 {
			bw = 1000
		}
		args = append(args, "-b", fmt.Sprintf("%dm", bw))
	}

	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ksubdomain: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseLines(stdout.Bytes())
}

// ParseLines 解 ksubdomain --silent 输出。导出供测试用。
//
// ksubdomain 默认每行一个 subdomain（无 JSON）：
//
//	api.example.com
//	www.example.com
//
// 容错：
//   - 空行跳过
//   - 行内不是合法 RFC 1123 域名 → 跳过（防止 banner 残留 / 控制字符）
//   - 小写归一 + 去重
//   - 超 MaxSubdomains 截断
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
		name := strings.ToLower(line)
		// 仅接受 RFC 1123 合法域名；防 banner / 颜色控制字符 / "[+]" 等前缀
		if !hostRe.MatchString(name) {
			continue
		}
		// 进一步过滤 IP 形态（IPv4 全数字段 + 点也匹配 hostRe）
		if net.ParseIP(name) != nil {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		rows = append(rows, map[string]any{
			"name":   name,
			"source": "ksubdomain",
		})
		if len(rows) >= MaxSubdomains {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ksubdomain: scan output: %w", err)
	}
	return rows, nil
}

// readPositiveInt 从 settings 取数字字段（支持 float64 / int / json.Number）。
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
