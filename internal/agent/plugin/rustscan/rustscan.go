// Package rustscan 是 port_scan 任务的真插件（PR-S49；补 SPEC §2.5 端口快扫维度）。
//
// 调用方式：
//
//	rustscan -a <target> -g --no-config --ulimit 5000
//
// -a <target>：目标 IP / host / cidr（rustscan 自动展开 cidr）
// -g：greppable 输出（Open <ip>:<port>，便于 parse）
// --no-config：忽略 ~/.rustscan.toml，确保 CI / 容器内行为可复现
// --ulimit 5000：提升 file descriptor 上限避大量并发 socket 失败
//
// 与 nmap 的差异：rustscan 快速 SYN 预筛活端口；nmap 做服务版本 + 脚本深扫。
// 套件 chaining 范式：rustscan → nmap（rustscan 输出 host:port → nmap 重点扫）。
// SPEC §2.5 列 rustscan 为 L2 端口扫描首选（快扫）。
//
// 本 plugin 仅做端口发现，不调 nmap。返结果：{"host": ip, "port": <int>}。
//
// dev / CI 没装 rustscan：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package rustscan

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// binaryName rustscan 可执行文件名；可被测试覆盖。
var binaryName = "rustscan"

// MaxResults 单任务结果上限；64k 端口 × N 主机可能巨包，限 5000 既覆盖
// /22 子网快扫又防 ReportTaskResults stream error。
var MaxResults = 5000

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；rustscan 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "port_scan" }

// IsMock 给 Loop 判定是否走 sleep 节奏；真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 支持：
//   - "ports" (string)：端口列表，缺省 rustscan 全 1-65535。格式同 nmap "-p"。
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
		targetKind = "ip"
	}
	switch targetKind {
	case "ip", "host", "cidr":
	default:
		return nil, fmt.Errorf("rustscan: target_kind=%q 不支持（仅 ip/host/cidr）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, fmt.Errorf("rustscan: %w", err)
	}

	args := []string{"-a", target, "-g", "--no-config", "--ulimit", "5000"}
	if portsRaw, ok := settings["ports"].(string); ok {
		ports := strings.TrimSpace(portsRaw)
		if ports != "" {
			if err := safetarget.ValidatePorts(ports); err != nil {
				return nil, fmt.Errorf("rustscan: ports %w", err)
			}
			args = append(args, "-p", ports)
		}
	}

	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("rustscan: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseGreppable(stdout.Bytes())
}

// ParseGreppable 解 rustscan -g 输出。导出供测试用。
//
// greppable 输出形态（rustscan 2.x）：
//
//	192.0.2.1 -> [22,80,443]
//	192.0.2.2 -> [22]
//
// 也兼容老版 "Open <ip>:<port>" per-line 格式（rustscan 1.x）。
// 行内容不匹配则跳过。
func ParseGreppable(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 16)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// 形态 1: "192.0.2.1 -> [22,80,443]"
		if idx := strings.Index(line, "->"); idx > 0 {
			host := strings.TrimSpace(line[:idx])
			rest := strings.TrimSpace(line[idx+2:])
			rest = strings.TrimPrefix(rest, "[")
			rest = strings.TrimSuffix(rest, "]")
			for _, pStr := range strings.Split(rest, ",") {
				pStr = strings.TrimSpace(pStr)
				if pStr == "" {
					continue
				}
				port, err := strconv.Atoi(pStr)
				if err != nil || port <= 0 || port > 65535 {
					continue
				}
				rows = append(rows, map[string]any{"host": host, "port": port})
				if len(rows) >= MaxResults {
					return rows, nil
				}
			}
			continue
		}
		// 形态 2: "Open 192.0.2.1:80"
		if strings.HasPrefix(line, "Open ") {
			addr := strings.TrimPrefix(line, "Open ")
			colon := strings.LastIndex(addr, ":")
			if colon <= 0 {
				continue
			}
			host := strings.TrimSpace(addr[:colon])
			port, err := strconv.Atoi(strings.TrimSpace(addr[colon+1:]))
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			rows = append(rows, map[string]any{"host": host, "port": port})
			if len(rows) >= MaxResults {
				return rows, nil
			}
		}
		// 其他行（banner / progress 等）静默跳过
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("rustscan: scan output: %w", err)
	}
	return rows, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
