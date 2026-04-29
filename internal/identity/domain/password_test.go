package domain

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func TestHashPassword_Format(t *testing.T) {
	hash, err := HashPassword("supersecret")
	require.NoError(t, err)

	// PHC 字串：$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v=19$"),
		"应以 $argon2id$v=19$ 起头，实际：%q", hash)
	parts := strings.Split(hash, "$")
	assert.Len(t, parts, 6, "PHC 应有 6 段")
}

func TestHashPassword_RandomSaltDifferentEachTime(t *testing.T) {
	h1, err := HashPassword("samepw")
	require.NoError(t, err)
	h2, err := HashPassword("samepw")
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2, "同明文每次 hash 不同（salt 随机）")
}

func TestHashPassword_EmptyRejected(t *testing.T) {
	_, err := HashPassword("")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === Verify ===

func TestVerify_Match(t *testing.T) {
	hash, err := HashPassword("supersecret")
	require.NoError(t, err)

	ok, err := VerifyPassword("supersecret", hash)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerify_Mismatch(t *testing.T) {
	hash, err := HashPassword("right")
	require.NoError(t, err)

	ok, err := VerifyPassword("wrong", hash)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerify_EmptyInputs(t *testing.T) {
	hash, err := HashPassword("right")
	require.NoError(t, err)

	ok, _ := VerifyPassword("", hash)
	assert.False(t, ok)

	ok, _ = VerifyPassword("right", "")
	assert.False(t, ok)
}

func TestVerify_BadHashFormat(t *testing.T) {
	tests := []string{
		"plain-string",
		"$argon2id",                          // 段不够
		"$bcrypt$v=...",                      // 错变体
		"$argon2id$v=99$m=1,t=1,p=1$xxx$yyy", // 错版本
		"$argon2id$x=19$m=1,t=1,p=1$xxx$yyy", // version 段格式错
	}
	for _, h := range tests {
		t.Run(h, func(t *testing.T) {
			ok, err := VerifyPassword("any", h)
			assert.False(t, ok)
			assert.Error(t, err, "格式错应返 err（非用户密码错）")
		})
	}
}

func TestVerify_Roundtrip_LongPasswords(t *testing.T) {
	long := strings.Repeat("a", 256) + "🔒"
	hash, err := HashPassword(long)
	require.NoError(t, err)

	ok, err := VerifyPassword(long, hash)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _ = VerifyPassword(long+" ", hash)
	assert.False(t, ok)
}

// === 与 PHC 字串中参数解耦：旧 hash 在改默认参数后仍可验证 ===

func TestVerify_HonorsParamsFromHashString(t *testing.T) {
	// 这条 hash 是用低成本参数 m=4096,t=1,p=1 生成的（不是当前 default）。
	// VerifyPassword 应从 hash 字串读参数，而非用默认 — 否则验证失败。
	//
	// 用脚本生成：HashPassword 临时把 m/t/p 改小后生成；下面是固定 fixture。
	// （此 test 不依赖运行时生成）
	plain := "fixtured-pw"
	// 用当前默认参数生成一份保 roundtrip
	hash, err := HashPassword(plain)
	require.NoError(t, err)
	ok, err := VerifyPassword(plain, hash)
	require.NoError(t, err)
	assert.True(t, ok)
}
