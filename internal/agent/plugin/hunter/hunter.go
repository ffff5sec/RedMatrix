// Package hunter 是 subdomain 任务的 L1 适配器（PR-S54；SPEC §2.5 子域名维度
// 被动情报源）。
//
// Hunter（奇安信）是国内继 FOFA 后第二大被动资产情报源；通过其 OpenAPI 查
// domain="..." 拿子域 + URL 列表，覆盖率与 FOFA 互补。
//
// 调用方式（HTTP GET）：
//
//	GET https://hunter.qianxin.com/openApi/search
//	    ?api-key=<HUNTER_KEY>
//	    &search=<base64(domain="example.com")>
//	    &page=1
//	    &page_size=100
//
// 认证仅 api-key；MVP 不支持企业版扩展字段。
//
// 启动期 cmd/node 探测 env HUNTER_KEY；缺失 → New() 返 ErrNotInstalled。
package hunter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
)

// apiBaseURL Hunter API endpoint；可被测试覆盖。
var apiBaseURL = "https://hunter.qianxin.com/openApi/search"

// DefaultTimeout Hunter 查询通常 5-30s。
var DefaultTimeout = 60 * time.Second

// MaxSubdomains 单任务子域结果上限。
var MaxSubdomains = 500

// DefaultPageSize Hunter page_size 参数；上限 100。
const DefaultPageSize = 100

// hostRe 二次校；与其他 subdomain plugin 一致。
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	apiKey string
	client *http.Client
}

// New 构造；env HUNTER_KEY 缺失返 ErrNotInstalled。
func New() (*Plugin, error) {
	key := strings.TrimSpace(os.Getenv("HUNTER_KEY"))
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
// target 必须根域；query 用 domain="<target>"。
// settings 不读（MVP 不暴露 is_web / port_filter 等高级参数）。
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
		return nil, fmt.Errorf("hunter: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("hunter: %w", err)
	}

	// Hunter query: domain="example.com"；用 URL-safe base64（Hunter 文档要求）
	query := fmt.Sprintf(`domain="%s"`, target)
	qb64 := base64.URLEncoding.EncodeToString([]byte(query))

	q := url.Values{}
	q.Set("api-key", p.apiKey)
	q.Set("search", qb64)
	q.Set("page", "1")
	q.Set("page_size", fmt.Sprintf("%d", DefaultPageSize))
	endpoint := apiBaseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("hunter: build request: %w", err)
	}
	req.Header.Set("User-Agent", "RedMatrix/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hunter: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hunter: http %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("hunter: read body: %w", err)
	}
	return ParseResponse(raw)
}

// ParseResponse 解 Hunter API JSON 响应。导出供测试用。
//
// Hunter 响应结构：
//
//	{
//	  "code": 200,
//	  "data": {
//	    "total": 42,
//	    "arr": [
//	      {"url":"https://sub.example.com","ip":"1.2.3.4","port":443,"domain":"sub.example.com","status_code":200},
//	      ...
//	    ]
//	  },
//	  "message": "success"
//	}
//
// 错误响应：code != 200，message 含详情。
// 提取 arr[].domain（首选）；缺则从 url 字段解析 host。
func ParseResponse(raw []byte) ([]map[string]any, error) {
	var r hunterResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("hunter: json decode: %w", err)
	}
	if r.Code != 200 {
		return nil, fmt.Errorf("hunter: api error code=%d: %s", r.Code, r.Message)
	}
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for _, item := range r.Data.Arr {
		name := strings.ToLower(strings.TrimSpace(item.Domain))
		if name == "" && item.URL != "" {
			// fallback: 从 URL 字段解出 host
			if u, err := url.Parse(item.URL); err == nil {
				name = strings.ToLower(u.Hostname())
			}
		}
		if name == "" {
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
			"source": "hunter",
		}
		if item.IP != "" {
			row["ip"] = item.IP
		}
		if item.Port > 0 {
			row["port"] = item.Port
		}
		if item.StatusCode > 0 {
			row["status_code"] = item.StatusCode
		}
		rows = append(rows, row)
		if len(rows) >= MaxSubdomains {
			break
		}
	}
	return rows, nil
}

// hunterResponse Hunter API JSON 响应结构（仅本插件用到的字段）。
type hunterResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Total int          `json:"total"`
		Arr   []hunterItem `json:"arr"`
	} `json:"data"`
}

type hunterItem struct {
	URL        string `json:"url"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Domain     string `json:"domain"`
	StatusCode int    `json:"status_code"`
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
