// Package domain 是 asset 模块的领域模型（PR-S8）。
//
// Asset 是 scan_results 派生的"资产"——同一个 host / url / subdomain
// 在多次扫描中只存一行；result_count 累计、last_seen 滚动更新。
package domain

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Kind 资产类型。
type Kind string

const (
	KindHost      Kind = "host"      // port_scan / fingerprint 的 host
	KindSubdomain Kind = "subdomain" // subdomain 任务的 name
	KindURL       Kind = "url"       // web_crawl 的 url（去 query / fragment）
)

// Valid 校验合法值。
func (k Kind) Valid() bool {
	switch k {
	case KindHost, KindSubdomain, KindURL:
		return true
	}
	return false
}

// Asset 资产领域实体。
type Asset struct {
	ID          string
	TenantID    string
	ProjectID   string
	Kind        Kind
	Value       string // 已标准化（host 小写 / url 去 query）
	FirstSeen   time.Time
	LastSeen    time.Time
	ResultCount int
}

// ValidateForCreate INSERT/UPSERT 前校验。
func (a *Asset) ValidateForCreate() error {
	if a == nil {
		return errx.New(errx.ErrInvalidInput, "asset is nil")
	}
	if strings.TrimSpace(a.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "asset.tenant_id 不能为空")
	}
	if strings.TrimSpace(a.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "asset.project_id 不能为空")
	}
	if !a.Kind.Valid() {
		return errx.New(errx.ErrInvalidInput, "asset.kind 不合法").
			WithFields("got", string(a.Kind))
	}
	if strings.TrimSpace(a.Value) == "" {
		return errx.New(errx.ErrInvalidInput, "asset.value 不能为空")
	}
	if len(a.Value) > 2048 {
		return errx.New(errx.ErrInvalidInput, "asset.value 超长（>2048）")
	}
	return nil
}

// NormalizeHost 把 host 规范化：小写 + 去前后空白。
// "Example.COM" → "example.com"
func NormalizeHost(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizeURL 解析 + 规范化 URL：scheme + host + path（去 query / fragment）。
// 失败时返空（caller 跳过派生该 asset）。
func NormalizeURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	clean := &url.URL{
		Scheme: strings.ToLower(u.Scheme),
		Host:   strings.ToLower(u.Host),
		Path:   u.Path, // 保留路径大小写（path 区分大小写）
	}
	return clean.String()
}

// ErrInvalidDerivation 当 scan_result 数据无法派生 asset（比如 host 字段缺失）
// 时由派生函数返回；caller 通常静默跳过（result 仍入库，只是没派生 asset）。
var ErrInvalidDerivation = errors.New("asset: cannot derive from scan_result")

// IsStale 判定资产是否"老"：last_seen + threshold < now（PR-S31）。
//
// 用于 freshness UI：
//   - threshold ≤ 0 → 永远不老（兜底）
//   - last_seen 在 (now - threshold) 之前 → stale
//
// 与 PR-S30 套件 cron 增量模式配套：cron 每天扫的 suite 会让活资产
// last_seen 滚动；停滚 = 资产消失，可能下线 / 入侵替换。
func (a *Asset) IsStale(threshold time.Duration, now time.Time) bool {
	if a == nil || threshold <= 0 {
		return false
	}
	cutoff := now.Add(-threshold)
	return a.LastSeen.Before(cutoff)
}
