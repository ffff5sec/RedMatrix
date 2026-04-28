// Package bootstrapcheck 是 RedMatrix 启动期 "danger guard" 自检。
//
// 与 docs/LLD/40-deployment-detail.md §9.6 启动校验对齐：
//   - 抽样配置 / env，按 DefaultRules 检测疑似泄露凭据 / 弱默认 / 占位符
//   - 命中即 *errx.DomainError(ErrBootstrapGuardViolation) → cmd/server exit 2
//
// 不变量：
//   - Finding 的 Excerpt 永不暴露完整匹配值（保留 4+4 字符 + "***"）
//   - Rule.Match 必须是确定性纯函数（相同输入 → 相同输出）
//   - 默认规则误报优于漏报：宁可让运维显式 nolint 也不放过疑似泄露
//
// 范围：
//   - 已实现：DefaultRules（4 类）+ Scan + CheckConfig
//   - 待续：PKI 校验（CA 证书 / 私钥）/ ES index template / MinIO WORM mode
//     这些需要存储 client，留给后续 PR
package bootstrapcheck

import (
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Rule 是单条检测规则。
type Rule struct {
	// Name 是规则机器名（如 "AWSAccessKey"）；命中后写入 Finding.Pattern。
	Name string

	// Description 是给运维看的人话解释。
	Description string

	// Severity: "high" / "medium" / "low"。high 必须阻断启动；其余记录但可由
	// 调用方决定。当前 CheckConfig 只对 high 严打。
	Severity string

	// Match 接 value 返回是否命中。必须是纯函数。
	Match func(value string) bool
}

// Severity 取值。
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
	SeverityLow    = "low"
)

// Finding 是一条命中记录。
type Finding struct {
	// Source 是配置项的来源标识（如 "env:JWT_SECRET" / "config.Bootstrap.Password"）。
	Source string

	// Pattern 是命中的 Rule.Name。
	Pattern string

	// Description 直接复制自 Rule.Description。
	Description string

	// Severity 直接复制自 Rule.Severity。
	Severity string

	// Excerpt 是 value 的脱敏摘要（4 + *** + 4）。永不含完整明文。
	Excerpt string
}

// Guard 持有一组 Rule。零值不可用，用 NewGuard / Default。
type Guard struct {
	rules []Rule
}

// NewGuard 用任意 Rule 构造 Guard（测试用）。
func NewGuard(rules ...Rule) *Guard {
	return &Guard{rules: append([]Rule(nil), rules...)}
}

// Default 返回内置默认规则集（详见 rules.go DefaultRules）。
func Default() *Guard {
	return NewGuard(DefaultRules...)
}

// Scan 对每个 (key, value) 对应用所有 Rule，返回所有命中。
//
// 同一 (key, value) 命中多个 Rule 会产生多条 Finding。
// items 中 value 为空字串时跳过（空配置由 config.Validate 把关）。
func (g *Guard) Scan(items map[string]string) []Finding {
	if g == nil || len(g.rules) == 0 {
		return nil
	}
	var out []Finding
	for source, value := range items {
		if value == "" {
			continue
		}
		for _, rule := range g.rules {
			if rule.Match == nil {
				continue
			}
			if rule.Match(value) {
				out = append(out, Finding{
					Source:      source,
					Pattern:     rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Excerpt:     redact(value),
				})
			}
		}
	}
	return out
}

// CheckMap 是 Scan 的语义化包装：任一 high 严重度命中 → BOOTSTRAP_GUARD_VIOLATION。
// medium / low 仅记入 Findings 但不阻断启动（调用方自决处置）。
//
// 返回的 error 永远是 *errx.DomainError；调用方可 errors.As 取出 Findings：
//
//	var de *errx.DomainError
//	if errors.As(err, &de) {
//	    // de.Fields["findings"] 是 []Finding 的 fmt 字符串
//	}
func (g *Guard) CheckMap(items map[string]string) error {
	findings := g.Scan(items)
	if len(findings) == 0 {
		return nil
	}
	high := filterBySeverity(findings, SeverityHigh)
	if len(high) == 0 {
		return nil
	}
	// 拼一份脱敏摘要给 stderr / 日志
	summary := summarize(high)
	return errx.New(errx.ErrBootstrapGuardViolation,
		"启动期发现疑似泄露凭据 / 占位符 / 弱默认 — 请检查配置后再启动").
		WithFields("findings", summary, "count", len(high))
}

// redact 把 value 截短为 first4***last4 形式。短串全脱。
func redact(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:4] + "***" + v[len(v)-4:]
}

func filterBySeverity(findings []Finding, sev string) []Finding {
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func summarize(findings []Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.Source+":"+f.Pattern+"="+f.Excerpt)
	}
	return strings.Join(parts, ", ")
}
