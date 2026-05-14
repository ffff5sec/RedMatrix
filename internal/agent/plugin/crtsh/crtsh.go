// Package crtsh 是 subdomain 任务的 L1 适配器（PR-S53；SPEC §5.1 验收
// "L1 至少 1 个参考实现"）。
//
// L1 / L2 / L3 在 RedMatrix Plugin interface 层无区别——三层都是
// plugin.Plugin 实现，差异在于"实现技术":
//
//   - L1 适配器：API 集成（pure HTTP / SDK），无 CLI binary 依赖；典型如
//     FOFA / Hunter / Quake / crt.sh / 天眼查
//   - L2 包装器：CLI binary 调用，exec.LookPath 检测安装；典型如 nmap /
//     subfinder / nuclei / katana
//   - L3 POC：YAML 模板 + CEL（待 Phase 2）
//
// 选 crt.sh 作首个 L1 参考实现的理由：
//   - 公开 HTTPS：免 API Key，开箱即用
//   - SPEC §2.5 子域名维度的 CT 日志源（区别于 subfinder/amass 的多源聚合）
//   - 响应有 SAN 多域名一并暴露，对发现"未公开"子域有独特价值
//
// 调用方式（HTTP GET，无 CLI）：
//
//	GET https://crt.sh/?q=%25.<domain>&output=json
//
// %25.<domain> = "%.<domain>"（URL-encoded SQL LIKE 通配前缀）。
// crt.sh 响应 JSON array：
//
//	[{"issuer_ca_id":..,"name_value":"sub.example.com\nother.example.com",...}]
//
// name_value 可能含 \n 分隔多个 SAN 域名 + 通配 "*.example.com"。
package crtsh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// API endpoint base；可被测试覆盖（指向本地 httptest server）。
var apiBaseURL = "https://crt.sh/"

// DefaultTimeout crt.sh 大域查询有时 30-60s 才返回（CT 日志慢）。
var DefaultTimeout = 60 * time.Second

// MaxSubdomains 单任务子域结果上限（与 subfinder/amass/ksubdomain 同界）。
var MaxSubdomains = 500

// userAgent 让 crt.sh 后台能识别来源；遵守 API 礼节。
const userAgent = "RedMatrix/1.0 (+https://github.com/ffff5sec/RedMatrix)"

// hostRe RFC 1123 hostname 二次校（防 CT log 行内异常字符）。
var hostRe = regexp.MustCompile(`^[a-z0-9*]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9*]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	client *http.Client
}

// New 构造；不像 L2 那样依赖 binary —— 网络可达即可。
//
// 错误：唯一可能的失败是参数校验；HTTP 不在构造时探测（避免启动期阻塞）。
func New() (*Plugin, error) {
	return &Plugin{
		client: &http.Client{Timeout: DefaultTimeout},
	}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "subdomain" }

// IsMock 真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// target_kind 仅接受 "host"（域名）；CT 日志查询不支持 IP / CIDR。
// settings 不读（crt.sh 公开 API 无参数可调）。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	_ map[string]any,
) ([]map[string]any, error) {
	if p == nil || p.client == nil {
		return nil, plugin.ErrNotInstalled
	}
	target = strings.TrimSpace(target)
	if targetKind != "" && targetKind != "host" {
		return nil, fmt.Errorf("crtsh: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("crtsh: %w", err)
	}

	// 构造 query: %25.<domain> = LIKE '%.<domain>'
	q := url.Values{}
	q.Set("q", "%."+target)
	q.Set("output", "json")
	endpoint := apiBaseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("crtsh: http %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("crtsh: read body: %w", err)
	}
	return ParseResponse(raw)
}

// ParseResponse 解 crt.sh JSON array。导出供测试用。
//
// crt.sh 响应：
//
//	[{"name_value":"sub.example.com\nother.example.com","common_name":"...","issuer_ca_id":...},
//	 ...]
//
// 提取所有 name_value 行（\n 分隔），小写归一 + 去重 + 用 hostRe 二次校。
// 通配符 "*.example.com" 默认拒（hostRe 不接受 "*"）；如需保留通配，
// 修 hostRe 加 * 兜底——本实现选拒，仅入有效域名。
//
// 容错：响应非数组 / 空数组 → 返空切片；单条记录无 name_value 跳过。
func ParseResponse(raw []byte) ([]map[string]any, error) {
	var entries []crtshEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		// crt.sh 偶尔在大查询时返非 JSON HTML 错误页；按错处理而不是静默
		return nil, fmt.Errorf("crtsh: json decode: %w", err)
	}
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for _, e := range entries {
		raw := e.NameValue
		if raw == "" {
			continue
		}
		// name_value 单行可能含 \n 分隔多个 SAN
		for _, name := range strings.Split(raw, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			// 拒通配 "*.example.com"（hostRe 允许 * 在标签首位，但这里我们
			// 显式跳过：cmd 期望的是具体域，不是模式）
			if strings.HasPrefix(name, "*.") {
				continue
			}
			if !hostRe.MatchString(name) {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			rows = append(rows, map[string]any{
				"name":   name,
				"source": "crtsh",
			})
			if len(rows) >= MaxSubdomains {
				return rows, nil
			}
		}
	}
	return rows, nil
}

// crtshEntry crt.sh JSON 单条记录（仅本插件用到的字段）。
type crtshEntry struct {
	NameValue string `json:"name_value"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
