package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

func validCert() *NodeCertificate {
	now := time.Now().UTC()
	return &NodeCertificate{
		NodeID:       "00000000-0000-0000-0000-000000000aaa",
		SerialNumber: "1234567890",
		Fingerprint:  strings.Repeat("a", 64),
		CommonName:   "node-1",
		CertPEM:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
		IssuedAt:     now,
		ExpiresAt:    now.Add(30 * 24 * time.Hour),
	}
}

func TestNodeCertificate_ValidateForCreate_Happy(t *testing.T) {
	require.NoError(t, validCert().ValidateForCreate())
}

func TestNodeCertificate_ValidateForCreate_Errors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*NodeCertificate)
	}{
		{"empty node_id", func(c *NodeCertificate) { c.NodeID = "" }},
		{"empty serial", func(c *NodeCertificate) { c.SerialNumber = "" }},
		{"fingerprint 长度错", func(c *NodeCertificate) { c.Fingerprint = "deadbeef" }},
		{"empty CN", func(c *NodeCertificate) { c.CommonName = "" }},
		{"empty cert_pem", func(c *NodeCertificate) { c.CertPEM = "" }},
		{"expires_at 零值", func(c *NodeCertificate) { c.ExpiresAt = time.Time{} }},
		{"expires_at <= issued_at", func(c *NodeCertificate) {
			c.ExpiresAt = c.IssuedAt
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCert()
			tc.mut(c)
			err := c.ValidateForCreate()
			require.Error(t, err)
			code, _ := errx.GetCode(err)
			assert.Equal(t, errx.ErrInvalidInput, code)
		})
	}
}

func TestNodeCertificate_NilReceiver(t *testing.T) {
	var c *NodeCertificate
	require.Error(t, c.ValidateForCreate())
	assert.False(t, c.IsExpired(time.Now()))
	assert.False(t, c.IsRevoked())
	assert.False(t, c.IsValid(time.Now()))
}

func TestNodeCertificate_StateChecks(t *testing.T) {
	now := time.Now().UTC()
	c := validCert()
	c.ExpiresAt = now.Add(time.Hour)
	assert.True(t, c.IsValid(now))

	c.ExpiresAt = now.Add(-time.Minute)
	assert.True(t, c.IsExpired(now))
	assert.False(t, c.IsValid(now))

	c.ExpiresAt = now.Add(time.Hour)
	revoked := now
	c.RevokedAt = &revoked
	assert.True(t, c.IsRevoked())
	assert.False(t, c.IsValid(now))
}
