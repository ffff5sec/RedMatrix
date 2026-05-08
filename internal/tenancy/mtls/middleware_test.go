package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
)

// fakeCertRepo 只实现 Wrap 用到的 GetByFingerprint；其它方法 panic。
type fakeCertRepo struct {
	byFP map[string]*domain.NodeCertificate
}

func (f *fakeCertRepo) Insert(context.Context, *domain.NodeCertificate) error {
	panic("not used")
}
func (f *fakeCertRepo) GetBySerial(context.Context, string) (*domain.NodeCertificate, error) {
	panic("not used")
}
func (f *fakeCertRepo) GetByFingerprint(_ context.Context, fp string) (*domain.NodeCertificate, error) {
	c, ok := f.byFP[fp]
	if !ok {
		return nil, errx.New(errx.ErrNodeCertExpired, "not found")
	}
	return c, nil
}
func (f *fakeCertRepo) ListByNode(context.Context, string) ([]*domain.NodeCertificate, error) {
	panic("not used")
}
func (f *fakeCertRepo) Revoke(context.Context, string) error {
	panic("not used")
}

// signFreshCert 用真 CA 签一份新 leaf cert + 对应 domain 行；
// 返 (peer cert, domain.NodeCertificate)；测试可改 domain.NodeCertificate 模拟过期/吊销。
func signFreshCert(t *testing.T) (*x509.Certificate, *domain.NodeCertificate) {
	t.Helper()
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)
	leafKey, err := pki.NewLeafKey()
	require.NoError(t, err)
	leaf, _, err := ca.SignLeaf(leafKey.Public(), pki.SignLeafOptions{
		CommonName: "00000000-0000-0000-0000-000000000001",
		Usage:      pki.LeafUsageClient,
		Validity:   pki.DefaultLeafValidity,
		Now:        time.Now(),
	})
	require.NoError(t, err)
	now := time.Now()
	cert := &domain.NodeCertificate{
		NodeID:       "00000000-0000-0000-0000-000000000001",
		SerialNumber: leaf.SerialNumber.String(),
		Fingerprint:  pki.Fingerprint(leaf),
		CommonName:   "00000000-0000-0000-0000-000000000001",
		IssuedAt:     now.Add(-time.Minute),
		ExpiresAt:    now.Add(time.Hour),
	}
	return leaf, cert
}

// runReq 跑一次中间件包装的 GET /；
// peerCerts == nil → 模拟"没带客户端证书"；
// 返 (response, ctxNodeID).
func runReq(t *testing.T, mw *Middleware, peerCerts []*x509.Certificate) (*http.Response, string) {
	t.Helper()
	var captured string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = ctxmeta.NodeIDFromContext(r.Context())
	})
	server := httptest.NewServer(mw.Wrap(next))
	defer server.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	if peerCerts != nil {
		// httptest.Server 用 plain HTTP；我们手动塞一个伪 TLS 状态。
		// 直接从 http handler 入口走 ServeHTTP 反而更稳：避开 net 真握手。
		rec := httptest.NewRecorder()
		req.TLS = &tls.ConnectionState{PeerCertificates: peerCerts}
		mw.Wrap(next).ServeHTTP(rec, req)
		return rec.Result(), captured
	}
	// peerCerts == nil 走真 plain HTTP，让 r.TLS == nil
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp, captured
}

func TestMiddleware_NoPeerCert_401(t *testing.T) {
	mw, err := NewMiddleware(&fakeCertRepo{byFP: map[string]*domain.NodeCertificate{}}, nil)
	require.NoError(t, err)
	resp, nodeID := runReq(t, mw, nil)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, nodeID)
}

func TestMiddleware_UnknownFingerprint_401(t *testing.T) {
	leaf, _ := signFreshCert(t) // cert 没入 repo
	mw, err := NewMiddleware(&fakeCertRepo{byFP: map[string]*domain.NodeCertificate{}}, nil)
	require.NoError(t, err)
	resp, nodeID := runReq(t, mw, []*x509.Certificate{leaf})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, nodeID)
}

func TestMiddleware_RevokedCert_401(t *testing.T) {
	leaf, cert := signFreshCert(t)
	now := time.Now()
	cert.RevokedAt = &now
	mw, err := NewMiddleware(&fakeCertRepo{
		byFP: map[string]*domain.NodeCertificate{cert.Fingerprint: cert},
	}, nil)
	require.NoError(t, err)
	resp, nodeID := runReq(t, mw, []*x509.Certificate{leaf})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, nodeID)
}

func TestMiddleware_ExpiredCert_401(t *testing.T) {
	leaf, cert := signFreshCert(t)
	cert.ExpiresAt = time.Now().Add(-time.Hour) // 过期
	mw, err := NewMiddleware(&fakeCertRepo{
		byFP: map[string]*domain.NodeCertificate{cert.Fingerprint: cert},
	}, nil)
	require.NoError(t, err)
	resp, nodeID := runReq(t, mw, []*x509.Certificate{leaf})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, nodeID)
}

func TestMiddleware_ValidCert_PassesAndInjectsNodeID(t *testing.T) {
	leaf, cert := signFreshCert(t)
	mw, err := NewMiddleware(&fakeCertRepo{
		byFP: map[string]*domain.NodeCertificate{cert.Fingerprint: cert},
	}, nil)
	require.NoError(t, err)
	resp, nodeID := runReq(t, mw, []*x509.Certificate{leaf})
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, cert.NodeID, nodeID, "成功路径应把 node_id 注入 ctx")
}

func TestNewMiddleware_NilRepo(t *testing.T) {
	_, err := NewMiddleware(nil, nil)
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInternal, c)
}
