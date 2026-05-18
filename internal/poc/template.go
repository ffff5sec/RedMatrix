// Package poc 是 RedMatrix L3 声明式 POC 引擎（PR-S69，SPEC §2.4）。
//
// 形态：类 Nuclei YAML 模板 + 4 类 matcher（status / word / regex / dsl-CEL）。
// 当前 MVP 只覆盖 HTTP 协议、单 request；多 step / DNS / TCP 留 Phase 2。
//
// 与 L2 nuclei 插件的差异：
//   - L2 fork-exec nuclei 二进制（依赖外部安装）
//   - L3 RedMatrix 自己解析 YAML + 自己跑 matcher（无外部依赖，单容器即可分发）
//
// 模板布局：
//
//	templates/
//	├── exposures/
//	│   ├── server-status.yaml
//	│   └── git-config.yaml
//	└── ...
package poc

import (
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Template 单个 POC 模板。
type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

// Info 模板元数据。
type Info struct {
	Name      string   `yaml:"name"`
	Severity  Severity `yaml:"severity"`
	Author    string   `yaml:"author,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`
	Reference []string `yaml:"reference,omitempty"`
}

// Severity 5 级，与 finding/domain.Severity 字面量一致。
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Valid 判定 severity 合法。
func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// Request 单条 HTTP 请求 + 匹配条件。
type Request struct {
	// Method GET / POST / PUT / DELETE / HEAD；默认 GET。
	Method string `yaml:"method,omitempty"`
	// Path "/path"；执行时以 target 为 BaseURL 拼接。
	Path string `yaml:"path"`
	// Headers 请求头键值对。
	Headers map[string]string `yaml:"headers,omitempty"`
	// Body 请求体；纯文本（form / JSON 由 caller 自己编排）。
	Body string `yaml:"body,omitempty"`
	// Matchers 至少 1 条；全部 / 任一命中 = 整体命中（看 MatchersCondition）。
	Matchers []Matcher `yaml:"matchers"`
	// MatchersCondition "and"（默认） / "or"；任意大小写。
	MatchersCondition string `yaml:"matchers-condition,omitempty"`
}

// Matcher 单条匹配规则。type 决定哪些字段生效。
type Matcher struct {
	// Type 必填：status / word / regex / dsl。
	Type MatcherType `yaml:"type"`
	// Part 适用 word / regex：body / headers / status；默认 body。
	Part string `yaml:"part,omitempty"`
	// Status 适用 type=status：HTTP 状态码集，任一命中即算。
	Status []int `yaml:"status,omitempty"`
	// Words 适用 type=word：子串集。Condition 决定 and / or。
	Words []string `yaml:"words,omitempty"`
	// Regex 适用 type=regex：正则集。Condition 决定 and / or。
	Regex []string `yaml:"regex,omitempty"`
	// DSL 适用 type=dsl：CEL 表达式集，每条返 bool。Condition 决定 and / or。
	// 上下文：response.status (int)、response.body (string)、response.headers
	// (map[string][]string)。
	DSL []string `yaml:"dsl,omitempty"`
	// Condition 子条件聚合 "and"（默认） / "or"；适用 words / regex / dsl。
	Condition string `yaml:"condition,omitempty"`
	// Negative true = 取反命中。
	Negative bool `yaml:"negative,omitempty"`
}

// MatcherType 4 类。
type MatcherType string

const (
	MatcherStatus MatcherType = "status"
	MatcherWord   MatcherType = "word"
	MatcherRegex  MatcherType = "regex"
	MatcherDSL    MatcherType = "dsl"
)

// Valid 判定 type 合法。
func (m MatcherType) Valid() bool {
	switch m {
	case MatcherStatus, MatcherWord, MatcherRegex, MatcherDSL:
		return true
	}
	return false
}

// ValidateForLoad 模板加载后必跑：保证执行期不踩缺字段坑。
func (t *Template) ValidateForLoad() error {
	if t == nil {
		return errx.New(errx.ErrInvalidInput, "poc: template 为 nil")
	}
	if strings.TrimSpace(t.ID) == "" {
		return errx.New(errx.ErrInvalidInput, "poc: template.id 不能为空")
	}
	if strings.TrimSpace(t.Info.Name) == "" {
		return errx.New(errx.ErrInvalidInput, "poc: info.name 不能为空").
			WithFields("id", t.ID)
	}
	if !t.Info.Severity.Valid() {
		return errx.New(errx.ErrInvalidInput, "poc: info.severity 不合法").
			WithFields("id", t.ID, "got", string(t.Info.Severity))
	}
	if len(t.Requests) == 0 {
		return errx.New(errx.ErrInvalidInput, "poc: 至少需要 1 条 request").
			WithFields("id", t.ID)
	}
	for i := range t.Requests {
		if err := t.Requests[i].validate(t.ID, i); err != nil {
			return err
		}
	}
	return nil
}

func (r *Request) validate(tmplID string, idx int) error {
	if strings.TrimSpace(r.Path) == "" {
		return errx.New(errx.ErrInvalidInput, "poc: request.path 不能为空").
			WithFields("id", tmplID, "request_idx", idx)
	}
	if len(r.Matchers) == 0 {
		return errx.New(errx.ErrInvalidInput, "poc: request.matchers 至少 1 条").
			WithFields("id", tmplID, "request_idx", idx)
	}
	for j := range r.Matchers {
		if err := r.Matchers[j].validate(tmplID, idx, j); err != nil {
			return err
		}
	}
	return nil
}

func (m *Matcher) validate(tmplID string, reqIdx, matcherIdx int) error {
	if !m.Type.Valid() {
		return errx.New(errx.ErrInvalidInput, "poc: matcher.type 不合法").
			WithFields("id", tmplID, "request_idx", reqIdx, "matcher_idx", matcherIdx, "got", string(m.Type))
	}
	switch m.Type {
	case MatcherStatus:
		if len(m.Status) == 0 {
			return errx.New(errx.ErrInvalidInput, "poc: status matcher 缺 status 列表").
				WithFields("id", tmplID, "matcher_idx", matcherIdx)
		}
	case MatcherWord:
		if len(m.Words) == 0 {
			return errx.New(errx.ErrInvalidInput, "poc: word matcher 缺 words 列表").
				WithFields("id", tmplID, "matcher_idx", matcherIdx)
		}
	case MatcherRegex:
		if len(m.Regex) == 0 {
			return errx.New(errx.ErrInvalidInput, "poc: regex matcher 缺 regex 列表").
				WithFields("id", tmplID, "matcher_idx", matcherIdx)
		}
	case MatcherDSL:
		if len(m.DSL) == 0 {
			return errx.New(errx.ErrInvalidInput, "poc: dsl matcher 缺 dsl 列表").
				WithFields("id", tmplID, "matcher_idx", matcherIdx)
		}
	}
	return nil
}
