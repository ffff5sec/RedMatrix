// Package fingerprint 是 RedMatrix 内置指纹库（PR-S68，SPEC §2.5）。
//
// 用法：
//
//	lib := fingerprint.Default()
//	hits := lib.Match(scanResultData)  // []string{"WordPress", "nginx"}
//
// 调用方（scan.service）把 hits 合并进 result.data["tech"] 与 httpx 的内置
// detection 互补；侧重国内常见 stack（致远 OA / 用友 / 泛微 / 宝塔等）+ 通用
// Web 服务器 / 中间件。
//
// 规则 schema（rules.yaml）：
//
//	rules:
//	  - name: nginx               # 命中后写入 tech 列表的名字
//	    fields: [webserver]       # 限制查这些字段；为空 = 任意字符串字段
//	    keyword: nginx            # 大小写不敏感子串匹配
//	    case_sensitive: false     # 可选，默认 false
//
// 性能：规则数预计 < 200，每条结果走 O(rules × fields) 子串匹配，
// 对 web_crawl 上千页面体量也不阻塞（实测 1k 页面 × 50 规则 < 50ms）。
package fingerprint

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Rule 单条指纹规则。
type Rule struct {
	// Name 命中后写入的 tech 名称。
	Name string `yaml:"name" json:"name"`
	// Fields 限制只在这些字段查；为空 = 所有字符串 / 字符串数组字段。
	Fields []string `yaml:"fields,omitempty" json:"fields,omitempty"`
	// Keyword 子串匹配；空 = 永不命中（被静默跳过）。
	Keyword string `yaml:"keyword" json:"keyword"`
	// CaseSensitive false（默认）= 不区分大小写；true = 严格。
	CaseSensitive bool `yaml:"case_sensitive,omitempty" json:"case_sensitive,omitempty"`
	// Source 仅运行时填充；YAML 不读：
	//   "builtin" = 来自 rules.yaml 内嵌
	//   "custom"  = 来自 fingerprint_rules 表
	Source string `yaml:"-" json:"source,omitempty"`
}

// Library 加载后的规则库。零值不可用；用 NewLibrary 或 Default 构造。
type Library struct {
	rules []*Rule
}

// Rules 返规则切片（只读快照，调用方不应改）。
func (l *Library) Rules() []*Rule {
	if l == nil {
		return nil
	}
	return l.rules
}

// NewLibrary 从 YAML 字节加载规则。重复 name / 空 keyword 静默跳过。
func NewLibrary(yamlBytes []byte) (*Library, error) {
	var doc struct {
		Rules []*Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "fingerprint: parse rules yaml")
	}
	out := make([]*Rule, 0, len(doc.Rules))
	seen := map[string]struct{}{}
	for _, r := range doc.Rules {
		if r == nil {
			continue
		}
		if strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Keyword) == "" {
			continue
		}
		if _, dup := seen[r.Name]; dup {
			continue
		}
		seen[r.Name] = struct{}{}
		out = append(out, r)
	}
	return &Library{rules: out}, nil
}

// Match 对 scan_result.data 跑全部规则，返命中的 tech 名（去重 + 字典序排序）。
// 输入 nil 返 nil。
func (l *Library) Match(data map[string]any) []string {
	if l == nil || len(l.rules) == 0 || len(data) == 0 {
		return nil
	}
	hits := map[string]struct{}{}
	for _, r := range l.rules {
		if r.matches(data) {
			hits[r.Name] = struct{}{}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	out := make([]string, 0, len(hits))
	for name := range hits {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// matches 单条规则对 data 是否命中。
func (r *Rule) matches(data map[string]any) bool {
	needle := r.Keyword
	if !r.CaseSensitive {
		needle = strings.ToLower(needle)
	}
	// fields 过滤：空 = 任意字符串字段；否则只检指定字段
	if len(r.Fields) == 0 {
		for _, text := range extractTextFields(data) {
			if r.hitText(text, needle) {
				return true
			}
		}
		return false
	}
	for _, fname := range r.Fields {
		v, ok := data[fname]
		if !ok {
			continue
		}
		for _, text := range valueToText(v) {
			if r.hitText(text, needle) {
				return true
			}
		}
	}
	return false
}

func (r *Rule) hitText(text, needle string) bool {
	if !r.CaseSensitive {
		text = strings.ToLower(text)
	}
	return strings.Contains(text, needle)
}

// extractTextFields 从 data 抽全部 string / []string / []any[string] 值。
func extractTextFields(data map[string]any) []string {
	out := make([]string, 0, len(data))
	for _, v := range data {
		out = append(out, valueToText(v)...)
	}
	return out
}

// valueToText 把 any 转字符串切片：string → [s]；[]string → 自身；
// []any 取里面的 string；其他类型忽略。
func valueToText(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
