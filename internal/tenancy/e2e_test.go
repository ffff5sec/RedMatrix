package tenancy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/agent/client"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/mtls"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
)

// inlineNodeAgentHandler 重新实现一份 tenancyv1connect.NodeAgentServiceHandler，
// 避免 e2e_test.go → handler → tenancy 的循环 import。逻辑与
// internal/tenancy/handler/node_agent.go 等价。
type inlineNodeAgentHandler struct {
	svc Service
}

func (h *inlineNodeAgentHandler) Heartbeat(
	ctx context.Context,
	req *connect.Request[tenancyv1.HeartbeatRequest],
) (*connect.Response[tenancyv1.HeartbeatResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "no node_id in ctx"))
	}
	res, err := h.svc.Heartbeat(ctx, HeartbeatRequest{
		NodeID:  nodeID,
		Version: req.Msg.GetVersion(),
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&tenancyv1.HeartbeatResponse{
		ServerTime:      res.ServerTime.UTC().Format(time.RFC3339),
		IntervalSeconds: int32(res.Interval.Seconds()),
	}), nil
}

func (h *inlineNodeAgentHandler) PullTasks(
	context.Context,
	*connect.Request[tenancyv1.PullTasksRequest],
) (*connect.Response[tenancyv1.PullTasksResponse], error) {
	return connect.NewResponse(&tenancyv1.PullTasksResponse{}), nil
}

func (h *inlineNodeAgentHandler) ReportTaskProgress(
	context.Context,
	*connect.Request[tenancyv1.ReportTaskProgressRequest],
) (*connect.Response[tenancyv1.ReportTaskProgressResponse], error) {
	return connect.NewResponse(&tenancyv1.ReportTaskProgressResponse{}), nil
}

func (h *inlineNodeAgentHandler) ReportTaskResults(
	context.Context,
	*connect.Request[tenancyv1.ReportTaskResultsRequest],
) (*connect.Response[tenancyv1.ReportTaskResultsResponse], error) {
	return connect.NewResponse(&tenancyv1.ReportTaskResultsResponse{}), nil
}

func (h *inlineNodeAgentHandler) ReissueCert(
	ctx context.Context,
	_ *connect.Request[tenancyv1.ReissueCertRequest],
) (*connect.Response[tenancyv1.ReissueCertResponse], error) {
	nodeID := ctxmeta.NodeIDFromContext(ctx)
	if nodeID == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errx.New(errx.ErrAuthFailed, "no node_id in ctx"))
	}
	res, err := h.svc.ReissueCert(ctx, ReissueCertRequest{NodeID: nodeID})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&tenancyv1.ReissueCertResponse{
		NodeCertPem:   res.CertPEM,
		NodeKeyPem:    res.KeyPEM,
		CaCertPem:     res.CACertPEM,
		Fingerprint:   res.Fingerprint,
		CertExpiresAt: res.CertExpiresAt.UTC().Format(time.RFC3339),
	}), nil
}

// TestE2E_EnrollAndHeartbeat 端到端验证 PR-T4 D2/D3/D4 整链：
//
//	CreateRegistrationToken
//	  → RedeemRegistrationToken   (D2: 自动签 cert)
//	  → store.Save                (D4)
//	  → mTLS dial + Heartbeat     (D3 server + D4 client)
//	  → mockNodeRepo.LastSeenAt + Status==online
//
// 不需 docker：repo 全 mock；CA / cert / mTLS 都是真的。
func TestE2E_EnrollAndHeartbeat(t *testing.T) {
	// === 1. 真 CA + tenancy.Service（全 mock repo）===
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)

	pr := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	cr := newMockCertRepo()
	users := newMockUserLookup()
	svc, err := NewService(pr, mr, nr, ar, tr, cr, users, ca)
	require.NoError(t, err)

	// === 2. 创建 + 兑换 token（直接通过 svc，跳过公开 RPC + auth；
	//   公开 Redeem RPC 已在 D2 测试覆盖）===
	tok, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "e2e"})
	require.NoError(t, err)

	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{
			Plaintext: tok.Plaintext,
			NodeName:  "e2e-agent",
			Version:   "test",
		})
	require.NoError(t, err)
	require.NotEmpty(t, rd.NodeCertPEM, "D2 应签发 cert")

	// === 3. agent store 落盘（D4）===
	dataDir := t.TempDir()
	st, err := store.New(dataDir)
	require.NoError(t, err)
	require.NoError(t, st.Save(&store.Enrollment{
		NodeID:    rd.Node.ID,
		CertPEM:   []byte(rd.NodeCertPEM),
		KeyPEM:    []byte(rd.NodeKeyPEM),
		CACertPEM: []byte(rd.CACertPEM),
	}))
	// 反加载，模拟"重启后读已 enroll"
	en, err := st.Load()
	require.NoError(t, err)
	assert.Equal(t, rd.Node.ID, en.NodeID)
	assert.FileExists(t, filepath.Join(dataDir, "node-cert.pem"))

	// === 4. 起真 mTLS http.Server（D3）===
	addr, shutdown := startTestMTLSServer(t, svc, ca, cr)
	defer shutdown()

	// === 5. 真 mTLS client（D4）调 Heartbeat ===
	naClient, err := client.MTLSNodeAgent(
		"https://"+addr,
		en,
		client.WithServerName("localhost"),
	)
	require.NoError(t, err)

	resp, err := naClient.Heartbeat(context.Background(),
		connect.NewRequest(&tenancyv1.HeartbeatRequest{Version: "test"}))
	require.NoError(t, err, "Heartbeat 必须经 mTLS 中间件 + handler + svc 全链路通过")
	assert.NotEmpty(t, resp.Msg.GetServerTime())
	assert.Equal(t, int32(domain.HeartbeatInterval/time.Second), resp.Msg.GetIntervalSeconds())

	// === 6. 验状态机：pending → online + last_seen_at 落地 ===
	persisted := nr.rows[rd.Node.ID]
	require.NotNil(t, persisted)
	assert.Equal(t, domain.NodeOnline, persisted.Status, "首次 heartbeat 应推 pending→online")
	require.NotNil(t, persisted.LastSeenAt)
	assert.WithinDuration(t, time.Now(), *persisted.LastSeenAt, 5*time.Second)
}

// TestE2E_HeartbeatRejectsRevokedCert 验证 mTLS 中间件能正确拒掉 revoke 后的 cert。
func TestE2E_HeartbeatRejectsRevokedCert(t *testing.T) {
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)
	pr := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	cr := newMockCertRepo()
	users := newMockUserLookup()
	svc, err := NewService(pr, mr, nr, ar, tr, cr, users, ca)
	require.NoError(t, err)

	tok, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "rev"})
	require.NoError(t, err)
	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: tok.Plaintext, NodeName: "rev-agent"})
	require.NoError(t, err)

	// Revoke 持久 cert（模拟管理员吊销）
	for id, c := range cr.rows {
		if c.NodeID == rd.Node.ID {
			require.NoError(t, cr.Revoke(context.Background(), id))
			break
		}
	}

	addr, shutdown := startTestMTLSServer(t, svc, ca, cr)
	defer shutdown()

	en := &store.Enrollment{
		NodeID:    rd.Node.ID,
		CertPEM:   []byte(rd.NodeCertPEM),
		KeyPEM:    []byte(rd.NodeKeyPEM),
		CACertPEM: []byte(rd.CACertPEM),
	}
	naClient, err := client.MTLSNodeAgent("https://"+addr, en, client.WithServerName("localhost"))
	require.NoError(t, err)

	_, err = naClient.Heartbeat(context.Background(),
		connect.NewRequest(&tenancyv1.HeartbeatRequest{}))
	require.Error(t, err, "已 Revoke 的 cert 必须被中间件拒掉")
}

// startTestMTLSServer 起一个真 mTLS http.Server 监 127.0.0.1:0，
// 复刻 cmd/server.startNodeAgentServer 的 TLS 配；返 addr + shutdown。
func startTestMTLSServer(t *testing.T, svc Service, ca *pki.CA, certRepo *mockCertRepo) (string, func()) {
	t.Helper()

	// 1. handler 链（用 inline impl 避循环 import）
	h := &inlineNodeAgentHandler{svc: svc}
	mw, err := mtls.NewMiddleware(certRepo, nil)
	require.NoError(t, err)
	path, raw := tenancyv1connect.NewNodeAgentServiceHandler(h)

	mux := http.NewServeMux()
	mux.Handle(path, mw.Wrap(raw))

	// 2. server leaf（SAN: localhost + 127.0.0.1）
	leafKey, err := pki.NewLeafKey()
	require.NoError(t, err)
	leaf, leafPEM, err := ca.SignLeaf(leafKey.Public(), pki.SignLeafOptions{
		CommonName: "localhost",
		DNSNames:   []string{"localhost"},
		IPs:        []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		Usage:      pki.LeafUsageServer,
		Validity:   pki.DefaultLeafValidity,
		Now:        time.Now(),
	})
	require.NoError(t, err)
	keyPEM, err := pki.MarshalLeafKeyPEM(leafKey)
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(leafPEM, keyPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := srv.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("e2e mTLS server crashed: %v", err)
		}
	}()
	// 等端口准备好（非常短）
	waitDial(t, addr)

	// 防 leaf 立刻过期警示：测试期内必然在 NotAfter 之内
	_ = leaf.NotAfter

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
	return addr, shutdown
}

// waitDial 轻量自旋等 TLS server 就绪（最多 1s）；mTLS 握手会挂一段时间，
// 这里仅探 TCP 端口可连。
func waitDial(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("e2e mTLS server 未在 1s 内就绪：%s", addr)
}
