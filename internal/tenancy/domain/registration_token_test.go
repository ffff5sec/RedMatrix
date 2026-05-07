package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validToken() *RegistrationToken {
	return &RegistrationToken{
		TenantID:  "00000000-0000-0000-0000-000000000001",
		Name:      "Q1 batch",
		TokenHash: strings.Repeat("a", 64),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
}

func TestRegistrationToken_ValidateForCreate_Happy(t *testing.T) {
	require.NoError(t, validToken().ValidateForCreate())
}

func TestRegistrationToken_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*RegistrationToken)
	}{
		{"empty tenant", func(t *RegistrationToken) { t.TenantID = "" }},
		{"empty name", func(t *RegistrationToken) { t.Name = "" }},
		{"name 超长", func(t *RegistrationToken) { t.Name = strings.Repeat("x", 65) }},
		{"hash 长度错", func(t *RegistrationToken) { t.TokenHash = "deadbeef" }},
		{"expires_at 零值", func(t *RegistrationToken) { t.ExpiresAt = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := validToken()
			tc.mut(tok)
			err := tok.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestRegistrationToken_NilReceiver(t *testing.T) {
	var tok *RegistrationToken
	require.Error(t, tok.ValidateForCreate())
	assert.False(t, tok.IsExpired(time.Now()))
	assert.False(t, tok.IsUsed())
	assert.False(t, tok.IsRevoked())
	assert.False(t, tok.IsUsable(time.Now()))
}

func TestRegistrationToken_StateChecks(t *testing.T) {
	now := time.Now().UTC()
	tok := validToken()
	tok.ExpiresAt = now.Add(time.Hour)
	assert.True(t, tok.IsUsable(now))
	assert.False(t, tok.IsExpired(now))

	tok.ExpiresAt = now.Add(-time.Minute)
	assert.True(t, tok.IsExpired(now))
	assert.False(t, tok.IsUsable(now))

	tok.ExpiresAt = now.Add(time.Hour)
	used := now
	tok.UsedAt = &used
	assert.True(t, tok.IsUsed())
	assert.False(t, tok.IsUsable(now))

	tok.UsedAt = nil
	tok.RevokedAt = &used
	assert.True(t, tok.IsRevoked())
	assert.False(t, tok.IsUsable(now))
}
