package poc

import (
	"regexp"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Match 整条 Request 的 matchers 命中判定（matchers-condition 控聚合）。
//
// 流程：逐条 matcher 评估，按 condition (and 默认 / or) 短路返。
func Match(req *Request, resp *Response) bool {
	if req == nil || resp == nil || len(req.Matchers) == 0 {
		return false
	}
	andMode := normalizeCondition(req.MatchersCondition, "and") == "and"
	for i := range req.Matchers {
		ok := evalMatcher(&req.Matchers[i], resp)
		if andMode && !ok {
			return false
		}
		if !andMode && ok {
			return true
		}
	}
	return andMode // and 全过 = true；or 全失败 = false
}

func evalMatcher(m *Matcher, resp *Response) bool {
	var ok bool
	switch m.Type {
	case MatcherStatus:
		ok = matchStatus(m.Status, resp.Status)
	case MatcherWord:
		ok = matchWord(m, resp)
	case MatcherRegex:
		ok = matchRegex(m, resp)
	case MatcherDSL:
		ok = matchDSL(m, resp)
	default:
		ok = false
	}
	if m.Negative {
		ok = !ok
	}
	return ok
}

func matchStatus(want []int, got int) bool {
	for _, s := range want {
		if s == got {
			return true
		}
	}
	return false
}

// matchWord 子串匹配。
//   - part: body（默认）/ headers / status
//   - condition: and / or（默认 or）
func matchWord(m *Matcher, resp *Response) bool {
	hay := extractPart(m.Part, resp)
	if hay == "" && len(m.Words) > 0 {
		return false
	}
	andMode := normalizeCondition(m.Condition, "or") == "and"
	hayLower := strings.ToLower(hay)
	for _, w := range m.Words {
		hit := strings.Contains(hayLower, strings.ToLower(w))
		if andMode && !hit {
			return false
		}
		if !andMode && hit {
			return true
		}
	}
	return andMode
}

func matchRegex(m *Matcher, resp *Response) bool {
	hay := extractPart(m.Part, resp)
	andMode := normalizeCondition(m.Condition, "or") == "and"
	for _, pat := range m.Regex {
		re, err := compileRegex(pat)
		if err != nil {
			// 编译失败视为不命中（不抛 error 让 caller 关心）
			if andMode {
				return false
			}
			continue
		}
		hit := re.MatchString(hay)
		if andMode && !hit {
			return false
		}
		if !andMode && hit {
			return true
		}
	}
	return andMode
}

// matchDSL 用 CEL 评估表达式集，每条返 bool。上下文：
//
//	response.status   int
//	response.body     string
//	response.headers  map(string, list(string))
func matchDSL(m *Matcher, resp *Response) bool {
	andMode := normalizeCondition(m.Condition, "or") == "and"
	env, err := getCELEnv()
	if err != nil {
		return false
	}
	celInput := map[string]any{
		"response": map[string]any{
			"status":  resp.Status,
			"body":    resp.Body,
			"headers": headersAsMap(resp.Headers),
		},
	}
	for _, expr := range m.DSL {
		hit := evalCELBool(env, expr, celInput)
		if andMode && !hit {
			return false
		}
		if !andMode && hit {
			return true
		}
	}
	return andMode
}

// === helpers ===

func extractPart(part string, resp *Response) string {
	switch strings.ToLower(strings.TrimSpace(part)) {
	case "", "body":
		return resp.Body
	case "headers":
		return headerString(resp.Headers)
	case "status":
		return itoa(resp.Status)
	}
	return ""
}

func headerString(h map[string][]string) string {
	if len(h) == 0 {
		return ""
	}
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func headersAsMap(h map[string][]string) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = v
	}
	return out
}

func normalizeCondition(s, def string) string {
	v := strings.ToLower(strings.TrimSpace(s))
	if v == "and" || v == "or" {
		return v
	}
	return def
}

// === regex cache ===

var (
	regexCacheMu sync.Mutex
	regexCache   = map[string]*regexp.Regexp{}
)

func compileRegex(pat string) (*regexp.Regexp, error) {
	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()
	if re, ok := regexCache[pat]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "poc: compile regex")
	}
	regexCache[pat] = re
	return re, nil
}

// === CEL env / cache ===

var (
	celEnvOnce sync.Once
	celEnv     *cel.Env
	celEnvErr  error

	celProgCacheMu sync.Mutex
	celProgCache   = map[string]cel.Program{}
)

func getCELEnv() (*cel.Env, error) {
	celEnvOnce.Do(func() {
		celEnv, celEnvErr = cel.NewEnv(
			cel.Variable("response", cel.DynType),
		)
	})
	return celEnv, celEnvErr
}

func evalCELBool(env *cel.Env, expr string, input map[string]any) bool {
	prog, err := getCELProgram(env, expr)
	if err != nil {
		return false
	}
	val, _, err := prog.Eval(input)
	if err != nil {
		return false
	}
	return celValToBool(val)
}

func getCELProgram(env *cel.Env, expr string) (cel.Program, error) {
	celProgCacheMu.Lock()
	defer celProgCacheMu.Unlock()
	if p, ok := celProgCache[expr]; ok {
		return p, nil
	}
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, iss.Err(), "poc: compile dsl")
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "poc: program dsl")
	}
	celProgCache[expr] = prog
	return prog, nil
}

func celValToBool(v ref.Val) bool {
	if b, ok := v.Value().(bool); ok {
		return b
	}
	return false
}

func itoa(n int) string {
	// strconv.Itoa 包内多个 file 用，统一这一处
	return intToString(n)
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
