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
)

// stubClient 是 NodeAgentServiceClient 的 in-memory 实现，仅提供 Heartbeat。
type stubClient struct {
	calls     atomic.Int32
	intervalS int32
	failFirst bool
	failEvery int32 // 每隔 N 次失败一次（0 = 永不失败）
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
