// Package nmap 是 port_scan 任务的真插件（PR-S9）。
//
// 调用方式：
//
//	nmap -sT -oX - -Pn --host-timeout 5m -p <ports> <target>
//
// -sT (TCP connect)：不需要 CAP_NET_RAW，容器友好；速度比 -sS 慢但够用 MVP
// -Pn：不做 ping 探测；扫云上禁 ICMP 的目标常见
// -oX -：XML 写 stdout
// --host-timeout 5m：单 host 5 分钟封顶
//
// 输出按 (host, port) 一行 → []map[string]any 给 ReportTaskResults。
//
// dev / CI 没装 nmap：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package nmap

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// DefaultPorts 默认扫端口范围。MVP 取 top-100 等价（手写常用列表，避免依赖
// nmap-services 文件路径）。后续按 settings.ports 覆盖。
const DefaultPorts = "21,22,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"

// binaryName nmap 可执行文件名；可被测试覆盖。
var binaryName = "nmap"

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；nmap 不在 PATH 时返 ErrNotInstalled。
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
// settings 可携：
//   - ports: string  覆盖默认端口列表（如 "1-1000"）
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	// url 不适合 port_scan；caller 应不该派；我们防御一下
	if targetKind == "url" {
		return nil, fmt.Errorf("nmap: target_kind=url 不支持 port_scan")
	}
	// PR-S17-SAFE：拒选项注入 / shell metachar / 非法格式
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}

	ports := DefaultPorts
	if settings != nil {
		if v, ok := settings["ports"].(string); ok && strings.TrimSpace(v) != "" {
			ports = strings.TrimSpace(v)
		}
	}
	if err := safetarget.ValidatePorts(ports); err != nil {
		return nil, fmt.Errorf("nmap: %w", err)
	}

	// "--" end-of-options 哨兵：把 target 推到 positional 区，让 nmap 不再当 option 解析
	args := []string{
		"-sT", "-Pn", "-oX", "-",
		"--host-timeout", "5m",
		"-p", ports,
		"--",
		target,
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseXML(stdout.Bytes())
}

// ParseXML 解 nmap -oX 输出。导出供测试用。
func ParseXML(xmlBytes []byte) ([]map[string]any, error) {
	var run nmapRun
	if err := xml.Unmarshal(xmlBytes, &run); err != nil {
		return nil, fmt.Errorf("nmap: parse xml: %w", err)
	}
	out := make([]map[string]any, 0, 16)
	for i := range run.Hosts {
		h := &run.Hosts[i]
		hostStr := bestAddr(h)
		if hostStr == "" {
			continue
		}
		for j := range h.Ports.Ports {
			port := &h.Ports.Ports[j]
			if port.State.State != "open" {
				continue
			}
			row := map[string]any{
				"host":    hostStr,
				"port":    port.PortID,
				"service": port.Service.Name,
			}
			if banner := port.Service.banner(); banner != "" {
				row["banner"] = banner
			}
			out = append(out, row)
		}
	}
	return out, nil
}

func bestAddr(h *nmapHost) string {
	// 优先 ipv4，回退 ipv6 / mac
	for i := range h.Addrs {
		a := &h.Addrs[i]
		if a.AddrType == "ipv4" {
			return a.Addr
		}
	}
	for i := range h.Addrs {
		a := &h.Addrs[i]
		if a.Addr != "" {
			return a.Addr
		}
	}
	// 回退 hostnames
	for i := range h.Hostnames.Hostnames {
		hn := &h.Hostnames.Hostnames[i]
		if hn.Name != "" {
			return hn.Name
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// === nmap XML 结构（仅取所需字段） ===

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addrs     []nmapAddr    `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
}

// banner 拼 product + version + extrainfo；都空返 ""。
func (s nmapService) banner() string {
	parts := []string{}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	if s.ExtraInfo != "" {
		parts = append(parts, "("+s.ExtraInfo+")")
	}
	return strings.Join(parts, " ")
}
