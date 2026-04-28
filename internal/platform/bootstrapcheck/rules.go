package bootstrapcheck

import (
	"regexp"
	"strings"
)

// DefaultRules 是开箱即用的检测规则集。每条都是 *high* 严重度（命中阻断启动）。
//
// 列表顺序无关；Scan 会遍历全部。增加新规则前请权衡误报风险（运维体感比漏报更敏感）。
var DefaultRules = []Rule{
	rulePlaceholderToken,
	ruleAWSAccessKey,
	rulePrivateKeyPEM,
	ruleWeakDefault,
}

// rulePlaceholderToken 匹配未替换的 .env.example / docs 占位符。
//
// 关键字段 set 为 CHANGEME / your-secret 等说明运维直接拿示例文件上线，
// 这是最常见的误配。所有占位符大小写不敏感。
var rulePlaceholderToken = Rule{
	Name:        "PlaceholderToken",
	Description: "未替换 .env.example / 文档示例占位符（CHANGEME / your-secret 等）",
	Severity:    SeverityHigh,
	Match: func(v string) bool {
		upper := strings.ToUpper(v)
		patterns := []string{
			"CHANGEME",
			"REPLACE_ME",
			"REPLACE-ME",
			"YOUR-SECRET",
			"YOUR_SECRET",
			"YOUR-PASSWORD",
			"YOUR_PASSWORD",
			"PLACEHOLDER",
			"TODO_FILL_IN",
			"TBD_SECRET",
			"INSERT_HERE",
		}
		for _, p := range patterns {
			if strings.Contains(upper, p) {
				return true
			}
		}
		return false
	},
}

// ruleAWSAccessKey 匹配 AWS access key 格式（AKIA + 16 个大写字母数字）。
// AWS_SECRET 则不易识别（40 字符 base64 误报多），暂不加。
var awsAccessKeyRe = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

var ruleAWSAccessKey = Rule{
	Name:        "AWSAccessKey",
	Description: "疑似 AWS Access Key（AKIA 开头 20 字符）",
	Severity:    SeverityHigh,
	Match:       awsAccessKeyRe.MatchString,
}

// rulePrivateKeyPEM 匹配 PEM 格式的私钥头部。
// 命中通常意味着误把整个 .pem 文件内容塞进 env / config，应改用 secrets 引用。
var rulePrivateKeyPEM = Rule{
	Name:        "PrivateKeyPEM",
	Description: "疑似 PEM 私钥块（-----BEGIN ... PRIVATE KEY-----）",
	Severity:    SeverityHigh,
	Match: func(v string) bool {
		return strings.Contains(v, "-----BEGIN") &&
			strings.Contains(v, "PRIVATE KEY-----")
	},
}

// ruleWeakDefault 匹配*完全相等*的弱默认值。
//
// 故意只查 "exactly equals"，不查 substring：避免把 "admin@example.com" 这种合法
// email 误判（contains "admin"）。这条规则的意图是抓 PASSWORD=admin / PASSWORD=root
// 这种粗糙误配，而不是模糊匹配。
//
// 大小写 + 前后空格容错。
var weakValues = map[string]struct{}{
	"admin":    {},
	"password": {},
	"123456":   {},
	"qwerty":   {},
	"root":     {},
	"test":     {},
	"letmein":  {},
	"default":  {},
	"123":      {},
	"1234":     {},
	"abc":      {},
	"abc123":   {},
	"changeme": {}, // 也作为 exact match 兜底（PlaceholderToken 走 substring）
}

var ruleWeakDefault = Rule{
	Name:        "WeakDefault",
	Description: "已知弱默认值 / 调试值（如 admin / password / root）",
	Severity:    SeverityHigh,
	Match: func(v string) bool {
		lv := strings.ToLower(strings.TrimSpace(v))
		_, ok := weakValues[lv]
		return ok
	},
}
