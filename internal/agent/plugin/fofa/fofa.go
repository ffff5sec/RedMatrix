// Package fofa 是 subdomain 任务的 L1 适配器（PR-S54；SPEC §2.5 子域名维度
// 被动情报源）。
//
// FOFA（白帽汇）是国内最大的被动资产情报源；通过其 OpenAPI 查 domain="..."
// 拿到全部已知 host 列表，覆盖率与 subfinder/amass 互补。
//
// 调用方式（HTTP GET）：
//
//	GET https://fofa.info/api/v1/search/all
//	    ?email=<FOFA_EMAIL>
//	    &key=<FOFA_KEY>
//	    &qbase64=<base64(domain="example.com")>
//	    &size=100
//	    &fields=host,ip,port
//
// 认证通过 email+key 两个 query 参数；MVP 不支持 vip token。
//
// 启动期 cmd/node 探测 env FOFA_EMAIL + FOFA_KEY；任一缺失 → New() 返
// ErrNotInstalled，cmd/node 回落 mock。
package fofa

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

// apiBaseURL FOFA API endpoint；可被测试覆盖。
var apiBaseURL = "https://fofa.info/api/v1/search/all"

// DefaultTimeout FOFA 大查询 30-60s 不少见。
var DefaultTimeout = 60 * time.Second

// MaxSubdomains 单任务子域结果上限（与其他 subdomain 插件同界）。
var MaxSubdomains = 500

// DefaultSize FOFA size 参数；上限 10000（API 限制）。
const DefaultSize = 100

// hostRe 二次校；与 ksubdomain/crtsh 一致。
var hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// Plugin 实现 plugin.Plugin。
type Plugin struct {
	email  string
	key    string
	client *http.Client
}

// New 构造；env FOFA_EMAIL + FOFA_KEY 任一缺失返 ErrNotInstalled。
func New() (*Plugin, error) {
	email := strings.TrimSpace(os.Getenv("FOFA_EMAIL"))
	key := strings.TrimSpace(os.Getenv("FOFA_KEY"))
	if email == "" || key == "" {
		return nil, plugin.ErrNotInstalled
	}
	return &Plugin{
		email:  email,
		key:    key,
		client: &http.Client{Timeout: DefaultTimeout},
	}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "subdomain" }

// IsMock 真插件返 false。
func (*Plugin) IsMock() bool { return false }

// Run 实现 Plugin。
//
// target 必须是根域名（host kind）；FOFA query 用 domain="<target>"。
// settings 不读（FOFA OpenAPI 参数少；size 走 DefaultSize）。
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
		return nil, fmt.Errorf("fofa: target_kind=%q 不支持（仅 host）", targetKind)
	}
	if err := safetarget.ValidateTarget(target, "host"); err != nil {
		return nil, fmt.Errorf("fofa: %w", err)
	}

	// FOFA query: domain="example.com"；base64 编码后塞 qbase64
	query := fmt.Sprintf(`domain="%s"`, target)
	qb64 := base64.StdEncoding.EncodeToString([]byte(query))

	q := url.Values{}
	q.Set("email", p.email)
	q.Set("key", p.key)
	q.Set("qbase64", qb64)
	q.Set("size", fmt.Sprintf("%d", DefaultSize))
	q.Set("fields", "host,ip,port")
	endpoint := apiBaseURL + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("fofa: build request: %w", err)
	}
	req.Header.Set("User-Agent", "RedMatrix/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fofa: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fofa: http %d: %s", resp.StatusCode, truncate(string(body), 256))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("fofa: read body: %w", err)
	}
	return ParseResponse(raw)
}

// ParseResponse 解 FOFA API JSON 响应。导出供测试用。
//
// FOFA 响应结构（fields=host,ip,port 时）：
//
//	{"error":false,"size":N,"page":1,"results":[
//	    ["sub.example.com:443","1.2.3.4","443"],
//	    ["api.example.com","5.6.7.8","80"],
//	    ...
//	]}
//
// 提取 results[i][0] 作 host 字段（可能含 ":port" 后缀，要剥）。
// 错误响应：
//
//	{"error":true,"errmsg":"[820001] API not found / quota exceeded"}
func ParseResponse(raw []byte) ([]map[string]any, error) {
	var r fofaResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("fofa: json decode: %w", err)
	}
	if r.Error {
		return nil, fmt.Errorf("fofa: api error: %s", r.ErrMsg)
	}
	rows := make([]map[string]any, 0, 16)
	seen := map[string]struct{}{}
	for _, item := range r.Results {
		if len(item) == 0 {
			continue
		}
		hostRaw, ok := item[0].(string)
		if !ok {
			continue
		}
		// FOFA host 字段可能含 ":port" 或 "scheme://host:port"；先剥
		hostRaw = strings.TrimSpace(hostRaw)
		if hostRaw == "" {
			continue
		}
		// 剥 scheme://
		if i := strings.Index(hostRaw, "://"); i > 0 {
			hostRaw = hostRaw[i+3:]
		}
		// 剥 :port
		if i := strings.IndexByte(hostRaw, ':'); i > 0 {
			hostRaw = hostRaw[:i]
		}
		name := strings.ToLower(hostRaw)
		if !hostRe.MatchString(name) {
			continue
		}
		// 进一步过滤 IP 形态（与 ksubdomain 同理：IP 也符 hostRe 模式）
		if net.ParseIP(name) != nil {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		row := map[string]any{
			"name":   name,
			"source": "fofa",
		}
		// 附加 IP / port 元数据若存在
		if len(item) > 1 {
			if ip, ok := item[1].(string); ok && ip != "" {
				row["ip"] = ip
			}
		}
		if len(item) > 2 {
			if port, ok := item[2].(string); ok && port != "" {
				row["port"] = port
			}
		}
		rows = append(rows, row)
		if len(rows) >= MaxSubdomains {
			break
		}
	}
	return rows, nil
}

// fofaResponse FOFA API JSON 响应结构。
type fofaResponse struct {
	Error   bool            `json:"error"`
	ErrMsg  string          `json:"errmsg"`
	Size    int             `json:"size"`
	Page    int             `json:"page"`
	Results [][]interface{} `json:"results"` // 每行是 fields 顺序的值
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
