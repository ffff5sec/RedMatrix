package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func TestGenerateAPIKey_Format(t *testing.T) {
	k, err := GenerateAPIKey()
	require.NoError(t, err)
	require.NotNil(t, k)

	// 长度
	assert.Len(t, k.Plaintext, APIKeyTokenLen)
	assert.Len(t, k.Prefix, APIKeyPrefixLen)
	assert.Len(t, k.SecretHash, 64) // SHA-256 hex

	// rmk_ 前缀
	assert.True(t, strings.HasPrefix(k.Plaintext, APIKeyTokenPrefix))

	// prefix 字符全在合法字母表
	for _, c := range k.Prefix {
		assert.Contains(t, apiKeyAlphabet, string(c), "prefix 含非法字符: %c", c)
	}

	// SecretHash 全 hex
	for _, c := range k.SecretHash {
		assert.Contains(t, "0123456789abcdef", string(c))
	}
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	// 30 bytes 熵 → 实际不可能撞；这里只防"返了同一个常量"的 bug
	seen := make(map[string]struct{}, 200)
	for i := 0; i < 200; i++ {
		k, err := GenerateAPIKey()
		require.NoError(t, err)
		_, dup := seen[k.Plaintext]
		require.False(t, dup, "200 次生成内不应碰撞")
		seen[k.Plaintext] = struct{}{}
	}
}

func TestParseAPIKey_Happy(t *testing.T) {
	k, err := GenerateAPIKey()
	require.NoError(t, err)

	prefix, secret, err := ParseAPIKey(k.Plaintext)
	require.NoError(t, err)
	assert.Equal(t, k.Prefix, prefix)
	assert.Len(t, secret, APIKeySecretLen)

	// 反查 hash 一致
	assert.Equal(t, k.SecretHash, HashAPIKeySecret(secret))
}

func TestParseAPIKey_Errors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"missing prefix", strings.Repeat("x", APIKeyTokenLen)},
		{"too short", "rmk_short"},
		{"too long", "rmk_" + strings.Repeat("A", APIKeyPrefixLen+APIKeySecretLen+5)},
		{"prefix has 0", "rmk_0BCDEFGH" + strings.Repeat("a", APIKeySecretLen)},
		{"prefix has I", "rmk_IBCDEFGH" + strings.Repeat("a", APIKeySecretLen)},
		{"prefix lowercase", "rmk_abcdefgh" + strings.Repeat("a", APIKeySecretLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseAPIKey(tc.raw)
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrAuthTokenInvalid, c)
		})
	}
}

func TestVerifyAPIKeySecret(t *testing.T) {
	k, err := GenerateAPIKey()
	require.NoError(t, err)
	_, secret, err := ParseAPIKey(k.Plaintext)
	require.NoError(t, err)

	assert.True(t, VerifyAPIKeySecret(secret, k.SecretHash))

	// 错答案
	assert.False(t, VerifyAPIKeySecret("wrong-secret", k.SecretHash))

	// 大小写敏感（hex hash）
	assert.False(t, VerifyAPIKeySecret(secret, strings.ToUpper(k.SecretHash)))

	// 长度不等
	assert.False(t, VerifyAPIKeySecret(secret, k.SecretHash[:32]))
}

func TestHashAPIKeySecret_Stable(t *testing.T) {
	a := HashAPIKeySecret("hello")
	b := HashAPIKeySecret("hello")
	assert.Equal(t, a, b, "同输入必同输出")
	assert.Len(t, a, 64)

	c := HashAPIKeySecret("hellow")
	assert.NotEqual(t, a, c)
}

func TestRandomFromAlphabet_Distribution(t *testing.T) {
	// 不严格测分布；只验长度 + 字母表合规 + 跨调用不返同串
	a, err := randomFromAlphabet(apiKeyAlphabet, 8)
	require.NoError(t, err)
	require.Len(t, a, 8)

	for _, c := range a {
		assert.Contains(t, apiKeyAlphabet, string(c))
	}

	// 1000 次跑没崩 + 没全相同
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		s, err := randomFromAlphabet(apiKeyAlphabet, 8)
		require.NoError(t, err)
		seen[s] = struct{}{}
	}
	assert.Greater(t, len(seen), 990, "1000 次内 8 字符 prefix 不应撞 ≥ 10 次")
}

func TestRandomFromAlphabet_Validates(t *testing.T) {
	_, err := randomFromAlphabet("", 8)
	require.Error(t, err)
}
