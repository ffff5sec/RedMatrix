package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateNodeToken_Format(t *testing.T) {
	tok, err := GenerateNodeToken()
	require.NoError(t, err)
	require.NotNil(t, tok)

	assert.Len(t, tok.Plaintext, NodeTokenTotalLen)
	assert.True(t, strings.HasPrefix(tok.Plaintext, NodeTokenPrefix))
	assert.Len(t, tok.Hash, 64)
	for _, c := range tok.Hash {
		assert.Contains(t, "0123456789abcdef", string(c))
	}
}

func TestGenerateNodeToken_Uniqueness(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 200; i++ {
		tok, err := GenerateNodeToken()
		require.NoError(t, err)
		_, dup := seen[tok.Plaintext]
		require.False(t, dup, "200 次生成不应碰撞")
		seen[tok.Plaintext] = struct{}{}
	}
}

func TestVerifyNodeToken_Roundtrip(t *testing.T) {
	tok, err := GenerateNodeToken()
	require.NoError(t, err)

	assert.True(t, VerifyNodeToken(tok.Plaintext, tok.Hash))

	// 修改 plaintext 一个字符 → 校验失败
	bad := tok.Plaintext[:len(tok.Plaintext)-1] + "x"
	assert.False(t, VerifyNodeToken(bad, tok.Hash))
	assert.False(t, VerifyNodeToken("", tok.Hash))
	assert.False(t, VerifyNodeToken(tok.Plaintext, ""))
}

func TestHashNodeToken_Stable(t *testing.T) {
	a := HashNodeToken("rmnode_abc")
	b := HashNodeToken("rmnode_abc")
	assert.Equal(t, a, b)
	assert.Len(t, a, 64)
	assert.NotEqual(t, a, HashNodeToken("rmnode_abd"))
}

func TestIsNodeTokenFormat(t *testing.T) {
	tok, err := GenerateNodeToken()
	require.NoError(t, err)
	assert.True(t, IsNodeTokenFormat(tok.Plaintext))

	assert.False(t, IsNodeTokenFormat(""))
	assert.False(t, IsNodeTokenFormat("rmnode_short"))
	assert.False(t, IsNodeTokenFormat("rmk_"+strings.Repeat("a", NodeTokenSecretLen)))
}
