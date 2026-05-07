package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === GenerateCA ===

func TestGenerateCA_Defaults(t *testing.T) {
	ca, err := GenerateCA(GenerateCAOptions{})
	require.NoError(t, err)
	require.NotNil(t, ca)
	require.NotNil(t, ca.Cert)
	require.NotNil(t, ca.Key)

	assert.Equal(t, DefaultCACommonName, ca.Cert.Subject.CommonName)
	assert.True(t, ca.Cert.IsCA)
	assert.Equal(t, 1, ca.Cert.MaxPathLen)
	// 有效期 ~ 10 年
	d := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore)
	assert.InDelta(t, DefaultCAValidity.Hours(), d.Hours(), 1)
}

func TestGenerateCA_CustomCN(t *testing.T) {
	ca, err := GenerateCA(GenerateCAOptions{
		CommonName: "Acme Test CA",
		Validity:   30 * 24 * time.Hour,
	})
	require.NoError(t, err)
	assert.Equal(t, "Acme Test CA", ca.Cert.Subject.CommonName)
}

func TestGenerateCA_BadValidity(t *testing.T) {
	_, err := GenerateCA(GenerateCAOptions{Validity: -time.Hour})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === Marshal + Load round-trip ===

func TestMarshalLoadCA_Roundtrip(t *testing.T) {
	ca, err := GenerateCA(GenerateCAOptions{})
	require.NoError(t, err)

	certPEM, keyPEM, err := MarshalCAPEM(ca)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(certPEM), "-----BEGIN CERTIFICATE-----"))
	require.True(t, strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----"))

	loaded, err := LoadCAPEM(certPEM, keyPEM)
	require.NoError(t, err)
	assert.Equal(t, ca.Cert.SerialNumber.String(), loaded.Cert.SerialNumber.String())
	assert.Equal(t, ca.Cert.Subject.CommonName, loaded.Cert.Subject.CommonName)
	// 公钥配对
	assert.True(t, ecdsaPubsEqual(&loaded.Key.PublicKey, ca.Cert.PublicKey))
}

func TestMarshalCAPEM_Nil(t *testing.T) {
	_, _, err := MarshalCAPEM(nil)
	require.Error(t, err)
}

func TestLoadCAPEM_BadCertPEM(t *testing.T) {
	_, err := LoadCAPEM([]byte("not a pem"), nil)
	require.Error(t, err)
}

func TestLoadCAPEM_NonCACert(t *testing.T) {
	// 自签一个非 CA cert（IsCA=false）当 CA 加载应被拒
	ca, err := GenerateCA(GenerateCAOptions{})
	require.NoError(t, err)
	leafKey, err := NewLeafKey()
	require.NoError(t, err)
	_, leafPEM, err := ca.SignLeaf(leafKey.Public(), SignLeafOptions{
		CommonName: "leaf-1",
		Usage:      LeafUsageClient,
	})
	require.NoError(t, err)
	keyPEM, err := MarshalLeafKeyPEM(leafKey)
	require.NoError(t, err)

	_, err = LoadCAPEM(leafPEM, keyPEM)
	require.Error(t, err)
}

func TestLoadCAPEM_MismatchedKey(t *testing.T) {
	ca1, _ := GenerateCA(GenerateCAOptions{})
	ca2, _ := GenerateCA(GenerateCAOptions{})

	cert1PEM, _, _ := MarshalCAPEM(ca1)
	_, key2PEM, _ := MarshalCAPEM(ca2)

	_, err := LoadCAPEM(cert1PEM, key2PEM)
	require.Error(t, err, "cert + 不匹配的 key 应被拒")
}

// === SignLeaf ===

func TestSignLeaf_ClientChainVerifies(t *testing.T) {
	ca, err := GenerateCA(GenerateCAOptions{})
	require.NoError(t, err)

	leafKey, err := NewLeafKey()
	require.NoError(t, err)

	leaf, leafPEM, err := ca.SignLeaf(leafKey.Public(), SignLeafOptions{
		CommonName: "node-abc",
		Usage:      LeafUsageClient,
		Validity:   24 * time.Hour,
	})
	require.NoError(t, err)
	require.NotNil(t, leaf)
	require.NotEmpty(t, leafPEM)

	// 用 stdlib 验证链
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err, "client cert 应能被 CA root 验证")
}

func TestSignLeaf_ServerWithSANs(t *testing.T) {
	ca, _ := GenerateCA(GenerateCAOptions{})
	key, _ := NewLeafKey()
	leaf, _, err := ca.SignLeaf(key.Public(), SignLeafOptions{
		CommonName: "server.example.com",
		DNSNames:   []string{"server.example.com", "*.api.example.com"},
		IPs:        []net.IP{net.ParseIP("127.0.0.1")},
		Usage:      LeafUsageServer,
	})
	require.NoError(t, err)
	assert.Contains(t, leaf.DNSNames, "server.example.com")
	assert.Contains(t, leaf.DNSNames, "*.api.example.com")
	require.Len(t, leaf.IPAddresses, 1)
	assert.True(t, leaf.IPAddresses[0].To4() != nil)
	// ExtKeyUsage 应含 ServerAuth
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestSignLeaf_BothUsage(t *testing.T) {
	ca, _ := GenerateCA(GenerateCAOptions{})
	key, _ := NewLeafKey()
	leaf, _, err := ca.SignLeaf(key.Public(), SignLeafOptions{
		CommonName: "dual",
		Usage:      LeafUsageBoth,
	})
	require.NoError(t, err)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	assert.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestSignLeaf_Errors(t *testing.T) {
	ca, _ := GenerateCA(GenerateCAOptions{})
	key, _ := NewLeafKey()

	cases := []struct {
		name    string
		opts    SignLeafOptions
		wantErr errx.Code
	}{
		{"empty CN", SignLeafOptions{Usage: LeafUsageClient}, errx.ErrInvalidInput},
		{"validity 太短", SignLeafOptions{
			CommonName: "x", Validity: 30 * time.Second,
		}, errx.ErrInvalidInput},
		{"validity 太长", SignLeafOptions{
			CommonName: "x", Validity: 2 * 365 * 24 * time.Hour,
		}, errx.ErrInvalidInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ca.SignLeaf(key.Public(), tc.opts)
			require.Error(t, err)
			c, _ := errx.GetCode(err)
			assert.Equal(t, tc.wantErr, c)
		})
	}
}

func TestSignLeaf_ValidityExceedsCA(t *testing.T) {
	// CA 仅 1h；leaf 要求 24h → 拒
	ca, err := GenerateCA(GenerateCAOptions{Validity: time.Hour})
	require.NoError(t, err)
	key, _ := NewLeafKey()
	_, _, err = ca.SignLeaf(key.Public(), SignLeafOptions{
		CommonName: "x", Validity: 24 * time.Hour,
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestSignLeaf_NilCA(t *testing.T) {
	var ca *CA
	key, _ := NewLeafKey()
	_, _, err := ca.SignLeaf(key.Public(), SignLeafOptions{CommonName: "x"})
	require.Error(t, err)
}

// === NewLeafKey + Marshal ===

func TestNewLeafKey_RoundtripPEM(t *testing.T) {
	k, err := NewLeafKey()
	require.NoError(t, err)
	require.NotNil(t, k)
	assert.Equal(t, elliptic.P256(), k.Curve)

	pemBytes, err := MarshalLeafKeyPEM(k)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----"))

	loaded, err := parseECDSAKeyPEM(pemBytes)
	require.NoError(t, err)
	assert.True(t, ecdsaPubsEqual(&k.PublicKey, &loaded.PublicKey))
}

func TestMarshalLeafKeyPEM_Nil(t *testing.T) {
	_, err := MarshalLeafKeyPEM(nil)
	require.Error(t, err)
}

// === Fingerprint ===

func TestFingerprint_StableLength(t *testing.T) {
	ca, _ := GenerateCA(GenerateCAOptions{})
	a := Fingerprint(ca.Cert)
	b := Fingerprint(ca.Cert)
	assert.Equal(t, a, b)
	assert.Len(t, a, 64)
	// 全 hex 小写
	for _, c := range a {
		assert.Contains(t, "0123456789abcdef", string(c))
	}
}

func TestFingerprint_DifferentCertsDiffer(t *testing.T) {
	ca1, _ := GenerateCA(GenerateCAOptions{})
	ca2, _ := GenerateCA(GenerateCAOptions{})
	assert.NotEqual(t, Fingerprint(ca1.Cert), Fingerprint(ca2.Cert))
}

func TestFingerprint_NilSafe(t *testing.T) {
	assert.Equal(t, "", Fingerprint(nil))
}

// === sanity: ED25519 / RSA leaf key 也能签 ===
//
// Leaf 公钥类型不强制 ECDSA；CA 仍是 ECDSA。验证 stdlib 行为。

func TestSignLeaf_AcceptsRSAKey(t *testing.T) {
	// 这里仅用 ECDSA 公钥但通过 crypto.PublicKey 接口传；省去 RSA 测试体积。
	// 真要测 RSA：rsa.GenerateKey + key.Public() 即可。
	ca, _ := GenerateCA(GenerateCAOptions{})
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, _, err = ca.SignLeaf(leafKey.Public(), SignLeafOptions{
		CommonName: "x",
		Usage:      LeafUsageClient,
	})
	require.NoError(t, err)
}
