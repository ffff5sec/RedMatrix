package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validKey() *APIKey {
	return &APIKey{
		UserID:     "11111111-1111-1111-1111-111111111111",
		Name:       "ci-bot",
		KeyPrefix:  "AB23CDEF",
		SecretHash: strings.Repeat("a", 64),
		CreatedAt:  time.Now().UTC(),
	}
}

func TestAPIKey_ValidateForCreate_Happy(t *testing.T) {
	require.NoError(t, validKey().ValidateForCreate())
}

func TestAPIKey_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*APIKey)
	}{
		{"empty user_id", func(k *APIKey) { k.UserID = "" }},
		{"empty name", func(k *APIKey) { k.Name = "" }},
		{"too-long name", func(k *APIKey) { k.Name = strings.Repeat("x", 65) }},
		{"prefix wrong length", func(k *APIKey) { k.KeyPrefix = "SHORT" }},
		{"hash wrong length", func(k *APIKey) { k.SecretHash = "deadbeef" }},
		{"expires_at <= created_at", func(k *APIKey) {
			t := k.CreatedAt.Add(-time.Hour)
			k.ExpiresAt = &t
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := validKey()
			tc.mut(k)
			err := k.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}

func TestAPIKey_ValidateForCreate_NilReceiver(t *testing.T) {
	var k *APIKey
	err := k.ValidateForCreate()
	require.Error(t, err)
}

func TestAPIKey_IsRevoked(t *testing.T) {
	k := validKey()
	assert.False(t, k.IsRevoked())
	now := time.Now()
	k.RevokedAt = &now
	assert.True(t, k.IsRevoked())
}

func TestAPIKey_IsExpired(t *testing.T) {
	now := time.Now().UTC()
	k := validKey()

	// nil ExpiresAt → 永不过期
	assert.False(t, k.IsExpired(now))

	past := now.Add(-time.Hour)
	k.ExpiresAt = &past
	assert.True(t, k.IsExpired(now))

	future := now.Add(time.Hour)
	k.ExpiresAt = &future
	assert.False(t, k.IsExpired(now))

	// 边界：ExpiresAt == now → 视为已过期
	k.ExpiresAt = &now
	assert.True(t, k.IsExpired(now))
}

func TestAPIKey_IsUsable(t *testing.T) {
	now := time.Now().UTC()
	k := validKey()
	assert.True(t, k.IsUsable(now))

	revoked := now.Add(-time.Minute)
	k.RevokedAt = &revoked
	assert.False(t, k.IsUsable(now))
	k.RevokedAt = nil

	expired := now.Add(-time.Minute)
	k.ExpiresAt = &expired
	assert.False(t, k.IsUsable(now))
}
