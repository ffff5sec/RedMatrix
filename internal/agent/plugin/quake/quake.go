// Package quake 是 subdomain 任务的 L1 适配器（PR-S55；SPEC §2.5 子域名维度
// 被动情报源）。
//
// Quake (奇虎 360) 是国内第三大网络空间测绘平台，资产覆盖与 FOFA / Hunter
// 互补——Quake 强在 IoT / 工控设备识别。
//
// 调用方式（HTTP POST）：
//
//	POST https://quake.360.net/api/v3/search/quake_service
//	Header: X-QuakeToken: <api_key>
//	Header: Content-Type: application/json
//	Body: {"query":"domain: \"example.com\"","start":0,"size":100}
//
// 与 FOFA / Hunter 的区别：
//   - FOFA: GET + email + key 两参，query base64
//   - Hunter: GET + api-key + search base64
//   - Quake: POST + X-QuakeToken header，body JSON 直传（无 base64）
//
// 启动期 cmd/node 探测 env QUAKE_KEY；缺失 → New() 返 ErrNotInstalled。
package quake

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// apiBaseURL Quake API endpoint；可被测试覆盖。
var apiBaseURL = "https://quake.360.net/api/v3/search/quake_service"

// DefaultTimeout Quake 大查询 30s 不少见。
var DefaultTimeout = 60 * time.Second

// MaxSubdomains 单任务结果上限。
var MaxSubdomains = 500

// DefaultSize Quake size 参数；上限 100（普通账号）/ 10000（VIP）。
const DefaultSize = 100

// hostRe 二次校；与其他 subdomain plugin 一致。
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	apiKey string
	client *http.Client
}

// New 构造；env QUAKE_KEY 缺失返 ErrNotInstalled。
func New() (*Plugin, error) {
	key := strings.TrimSpace(os.Getenv("QUAKE_KEY"))
	if key == "" {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{
		apiKey: key,
		client: &http.Client{Timeout: DefaultTimeout},
	}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "subdomain" }

// IsMock 真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// target 必须根域；Quake query 用 `domain: "<target>"`（Quake DSL）。
// settings 不读（MVP 不暴露 include / exclude / 高级时间过滤）。
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
		return nil, fmt.Errorf("quake: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("quake: %w", err)
	}

	// 构造 POST body JSON
	body := quakeRequest{
		Query: fmt.Sprintf(`domain: "%s"`, target),
		Start: 0,
		Size:  DefaultSize,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("quake: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBaseURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("quake: build request: %w", err)
	}
	req.Header.Set("X-QuakeToken", p.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RedMatrix/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("quake: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("quake: http %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("quake: read body: %w", err)
	}
	return ParseResponse(raw)
}

// ParseResponse 解 Quake API JSON 响应。导出供测试用。
//
// Quake 响应（v3 接口）：
//
//	{
//	  "code": 0,
//	  "message": "Successful.",
//	  "data": [
//	    {"hostname":"sub.example.com","ip":"1.2.3.4","port":443,"service":{...}},
//	    {"hostname":"","ip":"5.6.7.8","port":80}
//	  ],
//	  "meta": {...}
//	}
//
// 错误响应 code != 0；message 含描述（"u3001"=token 无效 / "u3008"=quota 用尽）。
// 提取 hostname；缺则跳过（hostname 空表示只发现 IP 资产，子域查询不入）。
func ParseResponse(raw []byte) ([]map[string]any, error) {
	var r quakeResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("quake: json decode: %w", err)
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("quake: api error code=%v: %s", r.Code, r.Message)
	}
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for _, item := range r.Data {
		name := strings.ToLower(strings.TrimSpace(item.Hostname))
		if name == "" {
			// Quake 偶尔 hostname 缺，仅有 IP；子域名 kind 跳过
			continue
		}
		if !hostRe.MatchString(name) {
			continue
		}
		if net.ParseIP(name) != nil {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		row := map[string]any{
			"name":   name,
			"source": "quake",
		}
		if item.IP != "" {
			row["ip"] = item.IP
		}
		if item.Port > 0 {
			row["port"] = item.Port
		}
		if item.Org != "" {
			row["org"] = item.Org
		}
		rows = append(rows, row)
		if len(rows) >= MaxSubdomains {
			break
		}
	}
	return rows, nil
}

// quakeRequest POST body 结构。
type quakeRequest struct {
	Query string `json:"query"`
	Start int    `json:"start"`
	Size  int    `json:"size"`
}

// quakeResponse Quake API JSON 响应结构（仅本插件用到的字段）。
//
// code 字段在不同子接口可能是 int (0) 或 string ("0")；用 json.RawMessage 推后再判。
// MVP 假定都是 int 0；如遇到 "0" 字符串会 decode 失败 → 返错。
type quakeResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    []quakeItem `json:"data"`
}

type quakeItem struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Org      string `json:"org"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
