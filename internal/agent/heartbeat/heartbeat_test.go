package heartbeat

import (
	"context"
	"errors"
	mathrand "math/rand"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
)

// signLeafForTest 用 ca 签一份 client cert + 返 (PEMs, NotAfter)。
func signLeafForTest(t *testing.T, ca *pki.CA, validity time.Duration) (certPEM, keyPEM []byte, notAfter time.Time) {
	t.Helper()
	leafKey, err := pki.NewLeafKey()
	require.NoError(t, err)
	leaf, certBytes, err := ca.SignLeaf(leafKey.Public(), pki.SignLeafOptions{
		CommonName: "00000000-0000-0000-0000-000000000abc",
		Usage:      pki.LeafUsageClient,
		Validity:   validity,
		Now:        time.Now(),
	})
	require.NoError(t, err)
	keyBytes, err := pki.MarshalLeafKeyPEM(leafKey)
	require.NoError(t, err)
	return certBytes, keyBytes, leaf.NotAfter
}

// stubClient 是 NodeAgentServiceClient 的 in-memory 实现。
type stubClient struct {
	calls     atomic.Int32
	intervalS int32
	failFirst bool
	failEvery int32 // 每隔 N 次失败一次（0 = 永不失败）

	// PR-T4-D5：续期路径
	reissueCalls atomic.Int32
	reissueResp  *tenancyv1.ReissueCertResponse // nil → 默认空响应（让 Loop 报错）
	reissueErr   error
}

func (s *stubClient) Heartbeat(_ context.Context, _ *connect.Request[tenancyv1.HeartbeatRequest]) (*connect.Response[tenancyv1.HeartbeatResponse], error) {
	n := s.calls.Add(1)
	if s.failFirst && n == 1 {
		return nil, errors.New("simulated first failure")
	}
	if s.failEvery > 0 && n%s.failEvery == 0 {
		return nil, errors.New("simulated periodic failure")
	}
	return connect.NewResponse(&tenancyv1.HeartbeatResponse{
		ServerTime:      time.Now().UTC().Format(time.RFC3339),
		IntervalSeconds: s.intervalS,
	}), nil
}

func (s *stubClient) PullTasks(_ context.Context, _ *connect.Request[tenancyv1.PullTasksRequest]) (*connect.Response[tenancyv1.PullTasksResponse], error) {
	return connect.NewResponse(&tenancyv1.PullTasksResponse{}), nil
}

func (s *stubClient) ReportTaskProgress(_ context.Context, _ *connect.Request[tenancyv1.ReportTaskProgressRequest]) (*connect.Response[tenancyv1.ReportTaskProgressResponse], error) {
	return connect.NewResponse(&tenancyv1.ReportTaskProgressResponse{}), nil
}

func (s *stubClient) ReissueCert(_ context.Context, _ *connect.Request[tenancyv1.ReissueCertRequest]) (*connect.Response[tenancyv1.ReissueCertResponse], error) {
	s.reissueCalls.Add(1)
	if s.reissueErr != nil {
		return nil, s.reissueErr
	}
	if s.reissueResp == nil {
		return connect.NewResponse(&tenancyv1.ReissueCertResponse{}), nil
	}
	return connect.NewResponse(s.reissueResp), nil
}

func TestLoop_NilDeps(t *testing.T) {
	var l *Loop
	require.Error(t, l.Run(context.Background()))
	l = &Loop{}
	require.Error(t, l.Run(context.Background()))
}

func TestLoop_FirstFailureAborts(t *testing.T) {
	l := &Loop{
		Client: &stubClient{failFirst: true},
		Logger: noopLogger{},
		Rand:   mathrand.New(mathrand.NewSource(1)),
	}
	err := l.Run(context.Background())
	require.Error(t, err)
}

func TestLoop_HappyPath_BeatsThenCancels(t *testing.T) {
	stub := &stubClient{intervalS: 0} // 0 → 用 DefaultInterval；jitter 后 ~27-33s
	l := &Loop{
		Client: stub,
		Logger: noopLogger{},
		Rand:   mathrand.New(mathrand.NewSource(1)),
	}
	// ctx 立即取消：第一次 beat 同步成功 → 进 select → ctx.Done → 退出
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := l.Run(ctx)
	assert.True(t, errors.Is(err, context.Canceled), "应返 context.Canceled，实际 %v", err)
	assert.GreaterOrEqual(t, stub.calls.Load(), int32(1), "至少跑一次首发")
}

func TestLoop_TransientErrorsLogged(t *testing.T) {
	// 让 server 给极短 interval（1s）+ 第二次以后随机失败；ctx 5s 后取消。
	stub := &stubClient{intervalS: 1, failEvery: 2}
	l := &Loop{
		Client: stub,
		Logger: noopLogger{},
		Rand:   mathrand.New(mathrand.NewSource(1)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := l.Run(ctx)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"err=%v calls=%d", err, stub.calls.Load())
	assert.Greater(t, stub.calls.Load(), int32(1), "应至少跑过 2 次")
}

func TestJitter_RangeBounds(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(42))
	base := time.Second * 30
	for range 1000 {
		got := jitter(base, rng)
		assert.GreaterOrEqual(t, got, base-base/10)
		// 严格 < base + base/10：base/5 是开区间上界（Int63n）
		assert.Less(t, got, base+base/10)
	}
}

func TestJitter_ZeroBaseFallsBackToDefault(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(1))
	assert.Equal(t, DefaultInterval, jitter(0, rng))
}

// === PR-T4-D5：续期 ===

func TestLoop_RenewTriggers_WhenCertNearExpiry(t *testing.T) {
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)

	// 旧 cert 寿命 1 分钟（pki.MinLeafValidity）；RenewBefore 设 90s 让它立即触发
	oldCert, oldKey, _ := signLeafForTest(t, ca, time.Minute)
	newCert, newKey, _ := signLeafForTest(t, ca, time.Hour) // 服务端"返"的新 cert
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nFAKE-CA\n-----END CERTIFICATE-----\n")

	dir := t.TempDir()
	st, err := store.New(dir)
	require.NoError(t, err)
	en := &store.Enrollment{
		NodeID:    "00000000-0000-0000-0000-000000000abc",
		CertPEM:   oldCert,
		KeyPEM:    oldKey,
		CACertPEM: caPEM,
	}
	require.NoError(t, st.Save(en))

	stub := &stubClient{
		intervalS: 0,
		reissueResp: &tenancyv1.ReissueCertResponse{
			NodeCertPem: string(newCert),
			NodeKeyPem:  string(newKey),
			CaCertPem:   string(caPEM),
			Fingerprint: "abc",
		},
	}

	rebuildCalled := atomic.Int32{}
	rebuild := func(e *store.Enrollment) (tenancyv1connect.NodeAgentServiceClient, error) {
		rebuildCalled.Add(1)
		// 复用同一个 stub（newCert 已落 enrollment，stub 不需感知）
		return stub, nil
	}

	l := &Loop{
		Client: stub,
		Logger: noopLogger{},
		Rand:   mathrand.New(mathrand.NewSource(1)),
		// 续期能力
		Store:         st,
		Enrollment:    en,
		RenewBefore:   90 * time.Second, // > 旧 cert 60s 寿命 → 立即触发
		RebuildClient: rebuild,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消，让 Loop 跑完 first beat + maybeRenew 后退出
	err = l.Run(ctx)
	assert.True(t, errors.Is(err, context.Canceled), "应返 ctx.Canceled，实际 %v", err)

	assert.Equal(t, int32(1), stub.reissueCalls.Load(), "应触发一次 ReissueCert")
	assert.Equal(t, int32(1), rebuildCalled.Load(), "应重建一次 mTLS client")

	// store 已被覆盖
	loaded, err := st.Load()
	require.NoError(t, err)
	assert.Equal(t, string(newCert), string(loaded.CertPEM), "新 cert 应已写盘")

	// Loop 内部 enrollment 也已替换
	assert.Equal(t, string(newCert), string(l.Enrollment.CertPEM))
}

func TestLoop_RenewSkipped_WhenCertFresh(t *testing.T) {
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)

	// cert 寿命 1 小时；RenewBefore 仅 60 秒 → 不触发
	cert, key, _ := signLeafForTest(t, ca, time.Hour)
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nFAKE-CA\n-----END CERTIFICATE-----\n")

	dir := t.TempDir()
	st, err := store.New(dir)
	require.NoError(t, err)
	en := &store.Enrollment{
		NodeID: "n", CertPEM: cert, KeyPEM: key, CACertPEM: caPEM,
	}
	require.NoError(t, st.Save(en))

	stub := &stubClient{}
	rebuild := func(e *store.Enrollment) (tenancyv1connect.NodeAgentServiceClient, error) {
		return stub, nil
	}
	l := &Loop{
		Client:        stub,
		Logger:        noopLogger{},
		Rand:          mathrand.New(mathrand.NewSource(1)),
		Store:         st,
		Enrollment:    en,
		RenewBefore:   time.Minute,
		RebuildClient: rebuild,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = l.Run(ctx)
	assert.Equal(t, int32(0), stub.reissueCalls.Load(), "fresh cert 不应触发续期")
}

func TestLoop_RenewSkipped_WhenDepsMissing(t *testing.T) {
	// canRenew() 任一字段缺失 → 不调 ReissueCert
	stub := &stubClient{}
	l := &Loop{
		Client: stub,
		Logger: noopLogger{},
		Rand:   mathrand.New(mathrand.NewSource(1)),
		// Store / Enrollment / RebuildClient 全 nil；RenewBefore 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = l.Run(ctx)
	assert.Equal(t, int32(0), stub.reissueCalls.Load())
}

func TestLoop_RenewFailureDoesNotBreakLoop(t *testing.T) {
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)
	cert, key, _ := signLeafForTest(t, ca, time.Minute)
	caPEM := []byte("-----BEGIN CERTIFICATE-----\nFAKE-CA\n-----END CERTIFICATE-----\n")

	dir := t.TempDir()
	st, err := store.New(dir)
	require.NoError(t, err)
	en := &store.Enrollment{NodeID: "n", CertPEM: cert, KeyPEM: key, CACertPEM: caPEM}
	require.NoError(t, st.Save(en))

	stub := &stubClient{
		reissueErr: errors.New("simulated ReissueCert RPC failure"),
	}
	rebuild := func(e *store.Enrollment) (tenancyv1connect.NodeAgentServiceClient, error) {
		return stub, nil
	}
	l := &Loop{
		Client:        stub,
		Logger:        noopLogger{},
		Rand:          mathrand.New(mathrand.NewSource(1)),
		Store:         st,
		Enrollment:    en,
		RenewBefore:   90 * time.Second,
		RebuildClient: rebuild,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = l.Run(ctx)
	// 续期失败不应让 Loop 错出（仅 ctx.Canceled）
	assert.True(t, errors.Is(err, context.Canceled), "Loop should still exit via ctx, got %v", err)
	assert.Equal(t, int32(1), stub.reissueCalls.Load())
	// store 没被改（ReissueCert 失败时不 Save）
	loaded, _ := st.Load()
	assert.Equal(t, string(cert), string(loaded.CertPEM), "失败时旧 cert 不应被覆盖")
}
