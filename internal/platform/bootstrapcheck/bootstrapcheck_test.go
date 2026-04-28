package bootstrapcheck

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === 单条规则 ===

func TestRule_PlaceholderToken(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{"CHANGEME", true},
		{"changeme_64chars", true},
		{"YOUR-SECRET-HERE", true},
		{"your_password", true},
		{"placeholder", true},
		{"abcdefghijklmnopqrstuvwxyz0123456789", false}, // 真随机
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.v, func(t *testing.T) {
			assert.Equal(t, tt.want, rulePlaceholderToken.Match(tt.v))
		})
	}
}

func TestRule_AWSAccessKey(t *testing.T) {
	assert.True(t, ruleAWSAccessKey.Match("AKIAIOSFODNN7EXAMPLE"))
	assert.True(t, ruleAWSAccessKey.Match("prefix AKIAIOSFODNN7EXAMPLE suffix"))
	assert.False(t, ruleAWSAccessKey.Match("AKIA"))
	assert.False(t, ruleAWSAccessKey.Match("akialong-but-lowercase-1234"))
	assert.False(t, ruleAWSAccessKey.Match(""))
}

func TestRule_PrivateKeyPEM(t *testing.T) {
	pem := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
	assert.True(t, rulePrivateKeyPEM.Match(pem))
	assert.True(t, rulePrivateKeyPEM.Match("-----BEGIN EC PRIVATE KEY-----"))
	assert.False(t, rulePrivateKeyPEM.Match("just a regular value"))
	assert.False(t, rulePrivateKeyPEM.Match("BEGIN PRIVATE KEY")) // 缺 -----
}

func TestRule_WeakDefault(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{"admin", true},
		{"ADMIN", true},
		{" admin ", true}, // trim 容错
		{"password", true},
		{"123456", true},
		{"root", true},
		{"admin@example.com", false}, // 不应误中（substring）
		{"administrator", false},     // 不应误中
		{"password123", false},       // 不应误中（exact only）
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.v, func(t *testing.T) {
			assert.Equal(t, tt.want, ruleWeakDefault.Match(tt.v))
		})
	}
}

// === Scan ===

func TestScan_NoFindings(t *testing.T) {
	g := Default()
	findings := g.Scan(map[string]string{
		"x": "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR",
		"y": "real_secure_password_with_entropy_123!@#",
	})
	assert.Empty(t, findings)
}

func TestScan_PlaceholderHits(t *testing.T) {
	g := Default()
	findings := g.Scan(map[string]string{
		"JWT_SECRET": "CHANGEME_64+chars_random_string",
	})
	require.Len(t, findings, 1)
	assert.Equal(t, "PlaceholderToken", findings[0].Pattern)
	assert.Equal(t, SeverityHigh, findings[0].Severity)
	assert.Equal(t, "JWT_SECRET", findings[0].Source)
	// Excerpt 必须脱敏
	assert.NotContains(t, findings[0].Excerpt, "CHANGEME_64+chars_random_string")
	assert.Equal(t, "CHAN***ring", findings[0].Excerpt)
}

func TestScan_MultipleRulesPerValue(t *testing.T) {
	g := Default()
	// "admin" 同时命中 WeakDefault；"-----BEGIN PRIVATE KEY-----" 命中 PrivateKeyPEM
	findings := g.Scan(map[string]string{
		"a": "admin",
		"b": "-----BEGIN PRIVATE KEY-----",
	})
	require.Len(t, findings, 2)
	patterns := []string{findings[0].Pattern, findings[1].Pattern}
	assert.Contains(t, patterns, "WeakDefault")
	assert.Contains(t, patterns, "PrivateKeyPEM")
}

func TestScan_EmptyValueSkipped(t *testing.T) {
	g := Default()
	findings := g.Scan(map[string]string{
		"unset_field": "",
	})
	assert.Empty(t, findings, "空值不参与扫描；缺失由 config.Validate 把关")
}

func TestScan_NilGuardSafe(t *testing.T) {
	var g *Guard
	assert.Empty(t, g.Scan(map[string]string{"x": "admin"}))
}

func TestScan_EmptyRulesSafe(t *testing.T) {
	g := NewGuard()
	assert.Empty(t, g.Scan(map[string]string{"x": "admin"}))
}

// === redact / Excerpt 不变量 ===

func TestRedact_LongValue(t *testing.T) {
	assert.Equal(t, "abcd***wxyz", redact("abcdefghijklmnopqrstuvwxyz"))
}

func TestRedact_ShortValueAllStars(t *testing.T) {
	assert.Equal(t, "*****", redact("admin"))
	assert.Equal(t, "********", redact("password"))
}

func TestRedact_NoLeak(t *testing.T) {
	v := "supersecret_password_value"
	out := redact(v)
	assert.NotContains(t, out, "supersecret")
	assert.NotContains(t, out, "password_value")
}

// === CheckMap ===

func TestCheckMap_NoHighFindingsReturnsNil(t *testing.T) {
	g := NewGuard(Rule{
		Name: "MediumOnly", Severity: SeverityMedium,
		Match: func(string) bool { return true },
	})
	err := g.CheckMap(map[string]string{"x": "anything"})
	assert.NoError(t, err, "medium 命中不阻断启动")
}

func TestCheckMap_HighFindingTriggersGuardViolation(t *testing.T) {
	g := Default()
	err := g.CheckMap(map[string]string{
		"JWT_SECRET": "CHANGEME",
	})
	require.Error(t, err)

	c, ok := errx.GetCode(err)
	require.True(t, ok)
	assert.Equal(t, errx.ErrBootstrapGuardViolation, c)

	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Contains(t, de.Fields["findings"], "PlaceholderToken")
	// stderr 不应泄漏完整原值
	assert.NotContains(t, de.Error(), "CHANGEME_64")
}

func TestCheckMap_MultipleFindingsSummarized(t *testing.T) {
	g := Default()
	err := g.CheckMap(map[string]string{
		"A": "admin",
		"B": "AKIAIOSFODNN7EXAMPLE",
	})
	require.Error(t, err)
	var de *errx.DomainError
	require.True(t, errors.As(err, &de))
	assert.Equal(t, 2, de.Fields["count"])
}

func TestCheckMap_NilGuardNoOp(t *testing.T) {
	var g *Guard
	assert.NoError(t, g.CheckMap(map[string]string{"x": "admin"}))
}

func TestCheckMap_EmptyItemsNil(t *testing.T) {
	g := Default()
	assert.NoError(t, g.CheckMap(nil))
	assert.NoError(t, g.CheckMap(map[string]string{}))
}

// === CheckConfig（直接用 config.Config）===

func TestCheckConfig_NilNoOp(t *testing.T) {
	assert.NoError(t, CheckConfig(nil))
}

func TestCheckConfig_PlaceholderInJWT(t *testing.T) {
	cfg := &config.Config{
		Crypto: config.CryptoConfig{JWTSecret: "CHANGEME_64+chars_random_string"},
	}
	err := CheckConfig(cfg)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrBootstrapGuardViolation, c)
}

func TestCheckConfig_WeakBootstrapPassword(t *testing.T) {
	cfg := &config.Config{
		Bootstrap: config.BootstrapAdmin{Password: "admin"},
	}
	err := CheckConfig(cfg)
	require.Error(t, err)
}

func TestCheckConfig_CleanConfigPasses(t *testing.T) {
	cfg := &config.Config{
		Crypto: config.CryptoConfig{
			JWTSecret: strings.Repeat("a", 64) + "0123456789",
		},
		Bootstrap: config.BootstrapAdmin{
			Username: "admin", // 用户名约定值；本字段不入凭据扫描
			Password: "",      // 留空 → 启动时随机
			Email:    "ops@example.com",
		},
		Public: config.PublicConfig{
			Domain: "redmatrix.example.com",
		},
		DB: config.DBConfig{
			MinIOAccessKey: "AKIA1234567890ABCDEF", // 这个会触发！让我们改下
			MinIOSecretKey: "real_secret_with_entropy_xyz_98765",
		},
	}
	// AKIA pattern 命中，故意构造的：实际 prod 不应使用 AKIA 格式 root key
	err := CheckConfig(cfg)
	require.Error(t, err, "AKIA 格式 access key 应触发")

	// 改用非 AKIA-格式的 access key
	cfg.DB.MinIOAccessKey = "minioadmin_with_entropy_xyz123"
	assert.NoError(t, CheckConfig(cfg))
}

// === Username 'admin' 是 LLD 04 §2.2 约定默认值，不应被扫描 ===
//
// 设计取舍：把 Username 放进扫描会让所有按文档默认配置的部署直接挂掉。
// CheckConfig 主动跳过 Bootstrap.Username 字段。

func TestCheckConfig_UsernameAdminAllowed(t *testing.T) {
	cfg := &config.Config{
		Bootstrap: config.BootstrapAdmin{Username: "admin"},
	}
	assert.NoError(t, CheckConfig(cfg), "Username='admin' 是文档默认值，跳过扫描")
}
