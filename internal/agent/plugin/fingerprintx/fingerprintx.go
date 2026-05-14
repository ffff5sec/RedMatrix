// Package fingerprintx 是 fingerprint 任务的真插件（PR-S51；补 SPEC §2.5
// 服务/技术栈 维度的多协议覆盖）。
//
// 调用方式：
//
//	fingerprintx -t <host:port,host:port,...> --json
//
// -t：目标列表，逗号分隔；缺端口时按 settings.ports 默认 list 笛卡尔扩展
// --json：JSON Lines 输出，每行一条服务识别结果
//
// 与 httpx 的差异：
//   - httpx：只识别 HTTP/HTTPS（status / title / tech 检测）
//   - fingerprintx：识别 30+ TCP/UDP 服务（SSH/FTP/SMTP/Redis/MySQL/Postgres/
//     MongoDB/Memcached/Kafka/NATS 等），并区分 TLS / plain 传输
//
// 两者同 kind=fingerprint；cmd/node 通过 FINGERPRINT_PLUGIN env 二选一。
// 部署多 agent 时可一组装 httpx 走 Web，一组装 fingerprintx 走非 Web 服务，
// 由 ScanTask 选 project / kind 路由（后续 Registry 聚合后可同 task 并跑）。
//
// dev / CI 没装 fingerprintx：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
package fingerprintx

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

// binaryName fingerprintx 可执行文件名；可被测试覆盖。
var binaryName = "fingerprintx"

// MaxResults 单任务结果上限。指纹结果通常 <100 行，留 500 兜底
// 避免 ReportTaskResults stream error。
var MaxResults = 500

// DefaultPorts 缺 settings.ports 时的默认探测端口（常见服务集）。
//
// 选取原则：覆盖 SPEC §2.5 提到的 "服务" 维度典型协议：
//   - Web: 80, 443, 8080, 8443
//   - 远程: 21 (ftp), 22 (ssh), 23 (telnet), 3389 (rdp)
//   - 邮件: 25 (smtp), 110 (pop3), 143 (imap)
//   - DB: 3306 (mysql), 5432 (postgres), 6379 (redis), 27017 (mongo), 1433 (mssql)
//   - 缓存/消息: 11211 (memcached), 9200 (es), 5672 (rabbit), 9092 (kafka)
const DefaultPorts = "21,22,23,25,80,110,143,443,1433,3306,3389,5432,5672,6379,8080,8443,9092,9200,11211,27017"

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；fingerprintx 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "fingerprint" }

// IsMock 给 Loop 判定是否走 sleep 节奏；真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// target 形态接受：
//   - "host" / "ip"：与 settings.ports 做笛卡尔积扩展
//   - "host:port"：单 target，settings.ports 忽略
//
// settings 支持：
//   - "ports" (string)：覆盖 DefaultPorts；逗号分隔，格式同 nmap "-p"
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("fingerprintx: target empty")
	}

	// 判定 target 是否已带 ":port"；若有则不再扩端口
	host, port := splitHostPort(target)
	hasPort := port != ""

	// 验 host（不含 port）部分
	if targetKind == "" {
		// host 形态默认 host；裸 IP 也能走 ip 校验
		if hasPort {
			targetKind = "host"
		} else {
			targetKind = "host"
		}
	}
	switch targetKind {
	case "host", "ip", "url":
	default:
		return nil, fmt.Errorf("fingerprintx: target_kind=%q 不支持（仅 host/ip/url）", targetKind)
	}
	// 用 host 部分 + 校 hostRe（已剥 :port）
	checkKind := targetKind
	if checkKind == "url" {
		// url 形态进 safetarget url 校；后续 fingerprintx -t 接 url-host:port
		if err := safetarget.ValidateTarget(target, "url"); err != nil {
			return nil, fmt.Errorf("fingerprintx: %w", err)
		}
	} else {
		// host / ip：host 部分单独校
		if err := safetarget.ValidateTarget(host, checkKind); err != nil {
			return nil, fmt.Errorf("fingerprintx: %w", err)
		}
	}

	// 构造 -t 参数：单 host:port 或 host × ports 笛卡尔积
	var tArg string
	if hasPort {
		tArg = host + ":" + port
	} else {
		ports := DefaultPorts
		if raw, ok := settings["ports"].(string); ok {
			ports = strings.TrimSpace(raw)
			if ports == "" {
				ports = DefaultPorts
			}
		}
		if err := safetarget.ValidatePorts(ports); err != nil {
			return nil, fmt.Errorf("fingerprintx: ports %w", err)
		}
		tArg = expandHostPorts(host, ports)
	}

	args := []string{"-t", tArg, "--json"}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("fingerprintx: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// splitHostPort 把 "host:port" 拆开；不含 ":" 返 (target, "")。
// 不验合法端口，仅切割；非数字端口会在下游 fingerprintx 自身拒。
//
// 注：不处理 IPv6 "[::1]:80" 形态——MVP 不接 IPv6 字面量 target。
func splitHostPort(s string) (host, port string) {
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s, "://") {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// expandHostPorts 把 "host" + "80,443,1-3" 展开为 "host:80,host:443,host:1,host:2,host:3"。
// 支持 nmap-style 端口范围 "a-b"（含两端）。
func expandHostPorts(host, ports string) string {
	parts := []string{}
	for _, seg := range strings.Split(ports, ",") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if i := strings.IndexByte(seg, '-'); i > 0 {
			loS, hiS := seg[:i], seg[i+1:]
			var lo, hi int
			_, errLo := fmt.Sscanf(loS, "%d", &lo)
			_, errHi := fmt.Sscanf(hiS, "%d", &hi)
			if errLo != nil || errHi != nil || lo > hi {
				continue
			}
			for p := lo; p <= hi && p <= 65535; p++ {
				parts = append(parts, fmt.Sprintf("%s:%d", host, p))
			}
			continue
		}
		var p int
		if _, err := fmt.Sscanf(seg, "%d", &p); err != nil || p <= 0 || p > 65535 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", host, p))
	}
	return strings.Join(parts, ",")
}

// ParseJSONLines 解 fingerprintx --json 输出。导出供测试用。
//
// fingerprintx v1.x JSON 行形态：
//
//	{"host":"example.com","ip":"93.184.216.34","port":443,
//	 "protocol":"https","tls":true,"transport":"tcp","version":""}
//
// 提取并归一：host / ip / port / protocol / transport / tls / version。
// 容错：单行 JSON 错跳过；host + ip 都空 → 跳过。
func ParseJSONLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 16)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry fpxEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(entry.Host))
		ip := strings.TrimSpace(entry.IP)
		if host == "" && ip == "" {
			continue
		}
		row := map[string]any{}
		// "target" 字段对齐 chain_extractor 期望（fingerprint kind 下游期望取
		// target 而非 host）；首选 host，缺则用 ip
		if host != "" {
			row["target"] = host
			row["host"] = host
		} else {
			row["target"] = ip
		}
		if ip != "" {
			row["ip"] = ip
		}
		if entry.Port > 0 {
			row["port"] = entry.Port
		}
		if entry.Protocol != "" {
			row["protocol"] = strings.ToLower(entry.Protocol)
		}
		if entry.Transport != "" {
			row["transport"] = strings.ToLower(entry.Transport)
		}
		if entry.TLS {
			row["tls"] = true
		}
		if entry.Version != "" {
			row["version"] = entry.Version
		}
		rows = append(rows, row)
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("fingerprintx: scan output: %w", err)
	}
	return rows, nil
}

// fpxEntry fingerprintx --json 单行结构（仅声明本插件用到的字段）。
type fpxEntry struct {
	Host      string `json:"host"`
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Transport string `json:"transport"`
	TLS       bool   `json:"tls"`
	Version   string `json:"version"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
