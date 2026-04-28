// Package es 包装 go-elasticsearch/v8 提供 RedMatrix 后端 Elasticsearch 客户端。
//
// 设计原则（docs/LLD/01-database-schema.md §2 + 04-config-schema.md §2.1 + 40 §4.2）：
//   - 单 client 多 address（HTTP+JSON；URL 可逗号分隔多节点）
//   - 启动期 Ping 调 _cluster/health，状态 red 拒绝启动；yellow / green 通过
//     （单节点档默认 yellow，HA 档 green）
//   - Username / Password 可选；MVP 部署默认禁用 xpack.security
//   - TLS 由 URL scheme 决定（http:// 不验，https:// 自动；CA 由系统 store 校验）
//
// 12 个 ES index 模板与 ILM policy 的 Put 由各模块仓库代码触发，不在本包。
package es

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Config ES 客户端配置（与 04-config-schema.md §3.1 connection_pools.es 段对齐）。
type Config struct {
	URL string // "http://es:9200" 或 "http://es1:9200,http://es2:9200"

	// 可选认证（MVP 默认空，对应 xpack.security.enabled=false）。
	Username string
	Password string

	MaxRetries  int
	DialTimeout time.Duration
}

const (
	defaultMaxRetries  = 3
	defaultDialTimeout = 5 * time.Second
)

// Client 包装 *elasticsearch.Client。Embed 让调用方直接走原生 API。
type Client struct {
	*elasticsearch.Client
}

// Open 解析 URL 并构造 client。不主动建连（lazy）。
func Open(_ context.Context, cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"ES URL 必填").WithFields("var", "ES_URL")
	}

	addrs := splitAddresses(cfg.URL)
	if len(addrs) == 0 {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"ES URL 解析后无有效地址").WithFields("var", "ES_URL")
	}

	// 校验每个地址 scheme + host
	for _, a := range addrs {
		u, err := url.Parse(a)
		if err != nil {
			return nil, errx.Wrap(errx.ErrBootstrapConfigInvalid, err,
				"ES URL 解析失败").WithFields("var", "ES_URL", "addr", a)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, errx.New(errx.ErrBootstrapConfigInvalid,
				"ES URL scheme 必须为 http / https").
				WithFields("var", "ES_URL", "got_scheme", u.Scheme)
		}
		if u.Host == "" {
			return nil, errx.New(errx.ErrBootstrapConfigInvalid,
				"ES URL 缺 host").WithFields("var", "ES_URL", "addr", a)
		}
	}

	cfg = withDefaults(cfg)
	es, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses:  addrs,
		Username:   cfg.Username,
		Password:   cfg.Password,
		MaxRetries: cfg.MaxRetries,
	})
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapConfigInvalid, err, "ES client 构造失败")
	}
	return &Client{Client: es}, nil
}

// Ping 调 _cluster/health 探活。
//
//   - 网络 / HTTP 错误 → BOOTSTRAP_DB_UNREACHABLE
//   - 4xx/5xx 状态码 → BOOTSTRAP_DB_UNREACHABLE
//   - cluster status=red → BOOTSTRAP_DB_UNREACHABLE
//   - yellow / green 通过
//
// 单节点档默认 yellow（副本无处分配），不应据此报错。
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.Client == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "ES client 未初始化")
	}

	res, err := c.Client.Cluster.Health(c.Client.Cluster.Health.WithContext(ctx))
	if err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err, "ES cluster health 请求失败")
	}
	defer res.Body.Close()

	if res.IsError() {
		return errx.New(errx.ErrBootstrapDBUnreachable,
			fmt.Sprintf("ES cluster health HTTP %d", res.StatusCode)).
			WithFields("status", res.StatusCode)
	}

	var h struct {
		Status      string `json:"status"`
		ClusterName string `json:"cluster_name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&h); err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err, "ES cluster health 响应解析失败")
	}

	if h.Status == "red" {
		return errx.New(errx.ErrBootstrapDBUnreachable,
			"ES cluster status=red（数据丢失风险，启动 abort）").
			WithFields("cluster", h.ClusterName)
	}
	return nil
}

// Health 返回 cluster 当前的简短状态，便于日志输出。
// 失败时返回 (status="", error)。
func (c *Client) Health(ctx context.Context) (status, clusterName string, err error) {
	if c == nil || c.Client == nil {
		return "", "", errors.New("ES client 未初始化")
	}
	res, err := c.Client.Cluster.Health(c.Client.Cluster.Health.WithContext(ctx))
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close()
	if res.IsError() {
		return "", "", fmt.Errorf("HTTP %d", res.StatusCode)
	}
	var h struct {
		Status      string `json:"status"`
		ClusterName string `json:"cluster_name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&h); err != nil {
		return "", "", err
	}
	return h.Status, h.ClusterName, nil
}

// Close 是占位（go-elasticsearch v8 client 无显式 Close；transport 由 GC 回收）。
func (c *Client) Close() error { return nil }

// Sanitize 把 URL 中的 userinfo 脱敏。逗号分隔多地址时分别脱敏并重新拼接。
func Sanitize(esURL string) string {
	if esURL == "" {
		return ""
	}
	parts := splitAddresses(esURL)
	if len(parts) == 0 {
		return "<invalid es url>"
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		u, err := url.Parse(p)
		if err != nil {
			out = append(out, "<invalid>")
			continue
		}
		out = append(out, u.Redacted())
	}
	return strings.Join(out, ",")
}

// splitAddresses 把 "a, b ,c" 或 "a,b,c" 拆成 ["a", "b", "c"]，空段过滤。
func splitAddresses(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func withDefaults(cfg Config) Config {
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	return cfg
}
