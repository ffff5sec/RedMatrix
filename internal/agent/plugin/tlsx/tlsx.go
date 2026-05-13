// Package tlsx 是 tls_scan 任务的真插件（PR-S48）。
//
// 调用方式：
//
//	tlsx -u <target> -j -silent [-port <port>]
//
// -u <target>：host / ip / url（tlsx 自动 strip URL 取 host:port）
// -j：JSON Lines 输出（每行一证书）
// -silent：屏蔽 banner / 进度
// -port：可选端口；缺省 443
//
// 输出每行解析：取 host / port / subject_cn / issuer_cn / not_before /
// not_after / sha256 fingerprint / sans / tls_version。
//
// dev / CI 没装 tlsx：New() 返 ErrNotInstalled，cmd/node 自动回落 mock。
//
// SPEC §2.5 资产发现矩阵证书行 + §2.7 一期事件 "证书到期"。
package tlsx

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

// binaryName tlsx 可执行文件名；可被测试覆盖。
var binaryName = "tlsx"

// MaxResults 单任务证书结果上限；防止巨包 stream error。
// 一个 host 通常 1-3 张（leaf + intermediates）；批量 SAN 扫场景下也罕见超 100。
var MaxResults = 200

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	bin string
}

// New 构造；tlsx 不在 PATH 时返 ErrNotInstalled。
func New() (*Plugin, error) {
	bin, err := exec.LookPath(binaryName)
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{bin: bin}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "tls_scan" }

// IsMock 给 Loop 判定是否走 sleep 节奏；真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// settings 支持：
//   - "port" (string)：覆盖默认 443，多端口逗号分隔（如 "443,8443"）。
//     tlsx 用 -port 收单一端口；多端口走逗号 list（tlsx -p 接 list 格式）。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	settings map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.bin == "" {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	// tlsx 接 host / ip / url 三种 target_kind。cidr 段不接（tlsx 不展开 CIDR）；
	// 上游 expansion 已把 cidr 展开成 ip 列表分发。
	if targetKind == "" {
		targetKind = "host"
	}
	switch targetKind {
	case "host", "ip", "url":
	case "cidr":
		return nil, fmt.Errorf("tlsx: target_kind=cidr 不支持（上游应已展开为 ip 列表）")
	default:
		return nil, fmt.Errorf("tlsx: target_kind=%q 不支持（仅 host/ip/url）", targetKind)
	}
	// PR-S17-SAFE：拒选项注入 / shell metachar / 格式错
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, fmt.Errorf("tlsx: %w", err)
	}

	args := []string{"-u", target, "-j", "-silent"}
	// 可选 port 覆盖
	if portRaw, ok := settings["port"].(string); ok {
		port := strings.TrimSpace(portRaw)
		if port != "" {
			if err := safetarget.ValidatePorts(port); err != nil {
				return nil, fmt.Errorf("tlsx: port %w", err)
			}
			args = append(args, "-p", port)
		}
	}

	cmd := exec.CommandContext(ctx, p.bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tlsx: exec failed: %w (stderr=%s)", err, truncate(stderr.String(), 256))
	}
	return ParseJSONLines(stdout.Bytes())
}

// ParseJSONLines 解 tlsx -j 输出（NDJSON）。导出供测试用。
//
// 字段映射（保留通用证书核心字段；忽略 tlsx 特有的 cipher detail / verifier）：
//
//	host                  → host
//	port                  → port (string)
//	subject_cn            → subject_cn
//	issuer_cn             → issuer_cn
//	not_before            → not_before (ISO-8601 string)
//	not_after             → not_after
//	fingerprint_hash.sha256 → sha256
//	subject_an            → sans ([]string)
//	tls_version           → tls_version
//	self_signed (bool)    → self_signed
//	wildcard_cert (bool)  → wildcard
//
// 容错：单行 JSON 错跳过；空行跳过。
func ParseJSONLines(out []byte) ([]map[string]any, error) {
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	rows := make([]map[string]any, 0, 16)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry tlsxEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			continue // 单行坏不毁全局
		}
		host := strings.TrimSpace(entry.Host)
		if host == "" {
			continue
		}
		row := map[string]any{
			"host": strings.ToLower(host),
		}
		if entry.Port != "" {
			row["port"] = entry.Port
		}
		if entry.SubjectCN != "" {
			row["subject_cn"] = entry.SubjectCN
		}
		if entry.IssuerCN != "" {
			row["issuer_cn"] = entry.IssuerCN
		}
		if entry.NotBefore != "" {
			row["not_before"] = entry.NotBefore
		}
		if entry.NotAfter != "" {
			row["not_after"] = entry.NotAfter
		}
		if entry.FingerprintHash.SHA256 != "" {
			row["sha256"] = entry.FingerprintHash.SHA256
		}
		if len(entry.SubjectAN) > 0 {
			// 复制切片防止下游意外修改
			sans := make([]string, len(entry.SubjectAN))
			copy(sans, entry.SubjectAN)
			row["sans"] = sans
		}
		if entry.TLSVersion != "" {
			row["tls_version"] = entry.TLSVersion
		}
		if entry.SelfSigned {
			row["self_signed"] = true
		}
		if entry.WildcardCert {
			row["wildcard"] = true
		}
		rows = append(rows, row)
		if len(rows) >= MaxResults {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("tlsx: scan output: %w", err)
	}
	return rows, nil
}

// tlsxEntry tlsx -j 单行结构（仅声明本插件用得到的字段）。
type tlsxEntry struct {
	Host            string   `json:"host"`
	Port            string   `json:"port"`
	SubjectCN       string   `json:"subject_cn"`
	IssuerCN        string   `json:"issuer_cn"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	SubjectAN       []string `json:"subject_an"`
	TLSVersion      string   `json:"tls_version"`
	SelfSigned      bool     `json:"self_signed"`
	WildcardCert    bool     `json:"wildcard_cert"`
	FingerprintHash struct {
		SHA256 string `json:"sha256"`
	} `json:"fingerprint_hash"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
