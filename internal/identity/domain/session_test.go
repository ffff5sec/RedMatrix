package domain

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validSession() *Session {
	now := time.Now().UTC()
	return &Session{
		ID:           "s1",
		TenantID:     "11111111-1111-1111-1111-111111111111",
		UserID:       "u1",
		UserAgent:    "go-test",
		IP:           netip.MustParseAddr("127.0.0.1"),
		IssuedAt:     now,
		LastSeenAt:   now,
		TokenVersion: 0,
		ExpiresAt:    now.Add(12 * time.Hour),
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now().UTC()
	s := &Session{IssuedAt: now, ExpiresAt: now.Add(time.Hour)}

	assert.False(t, s.IsExpired(now), "未到期不应判过期")
	assert.False(t, s.IsExpired(now.Add(59*time.Minute)), "59m 未到期")
	assert.True(t, s.IsExpired(now.Add(time.Hour)), "now == ExpiresAt 视为已过期")
	assert.True(t, s.IsExpired(now.Add(2*time.Hour)), "超过期限")
}

func TestSession_IsExpired_ZeroValueExpires(t *testing.T) {
	s := &Session{}
	assert.False(t, s.IsExpired(time.Now()), "ExpiresAt 零值视为未配置，不算过期")
}

func TestSession_ValidateForCreate_Happy(t *testing.T) {
	s := validSession()
	require.NoError(t, s.ValidateForCreate())
}

func TestSession_ValidateForCreate_Nil(t *testing.T) {
	var s *Session
	err := s.ValidateForCreate()
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestSession_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Session)
	}{
		{"empty user_id", func(s *Session) { s.UserID = "" }},
		{"negative tv", func(s *Session) { s.TokenVersion = -1 }},
		{"zero issued_at", func(s *Session) { s.IssuedAt = time.Time{} }},
		{"zero expires_at", func(s *Session) { s.ExpiresAt = time.Time{} }},
		{"expires <= issued", func(s *Session) { s.ExpiresAt = s.IssuedAt }},
		{"expires before issued", func(s *Session) { s.ExpiresAt = s.IssuedAt.Add(-time.Hour) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSession()
			tc.mut(s)
			err := s.ValidateForCreate()
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, c)
		})
	}
}
