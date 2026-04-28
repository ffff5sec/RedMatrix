package eventbus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 注：Relay 的 Run / processBatch 路径需要真实 PG，集成测试覆盖。
// 单测仅覆盖 backoff / 默认值 / 防御性。

func TestComputeBackoff_Exponential(t *testing.T) {
	r := &Relay{cfg: RelayConfig{
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		JitterRatio:    0, // 关掉 jitter 让断言可控
	}}

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1600 * time.Millisecond},
		{10, 10 * time.Second}, // 封顶
		{100, 10 * time.Second},
	}
	for _, tt := range tests {
		got := r.computeBackoff(tt.attempt)
		assert.Equalf(t, tt.want, got, "attempt=%d", tt.attempt)
	}
}

func TestComputeBackoff_JitterApplied(t *testing.T) {
	r := &Relay{cfg: RelayConfig{
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		JitterRatio:    0.5,
	}}

	// 100 次抽样：jitter ±50% 应让最大值与最小值显著分开
	min := time.Duration(1<<62) - 1
	var max time.Duration
	for i := 0; i < 100; i++ {
		d := r.computeBackoff(2) // base=200ms
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	assert.Less(t, min, max, "jitter 应产生不同结果")
	// 不强断绝对范围（随机性）；只确保在合理大区间
	assert.GreaterOrEqual(t, min, 50*time.Millisecond)
	assert.LessOrEqual(t, max, 400*time.Millisecond)
}

func TestComputeBackoff_NeverNegative(t *testing.T) {
	r := &Relay{cfg: RelayConfig{
		InitialBackoff: time.Microsecond,
		MaxBackoff:     time.Second,
		JitterRatio:    0.99, // 极端抖动
	}}
	for i := 0; i < 100; i++ {
		d := r.computeBackoff(1)
		assert.GreaterOrEqual(t, d, time.Duration(0))
	}
}

func TestWithRelayDefaults_AllZero(t *testing.T) {
	cfg := withRelayDefaults(RelayConfig{})
	assert.Equal(t, defaultPollInterval, cfg.PollInterval)
	assert.Equal(t, defaultBatchSize, cfg.BatchSize)
	assert.Equal(t, defaultMaxAttempts, cfg.MaxAttempts)
	assert.Equal(t, defaultInitialBackoff, cfg.InitialBackoff)
	assert.Equal(t, defaultMaxBackoff, cfg.MaxBackoff)
	assert.Equal(t, defaultJitterRatio, cfg.JitterRatio)
}

func TestWithRelayDefaults_Explicit(t *testing.T) {
	cfg := withRelayDefaults(RelayConfig{
		PollInterval:   1 * time.Second,
		BatchSize:      10,
		MaxAttempts:    3,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Minute,
		JitterRatio:    0.1,
	})
	assert.Equal(t, time.Second, cfg.PollInterval)
	assert.Equal(t, 10, cfg.BatchSize)
	assert.Equal(t, 3, cfg.MaxAttempts)
	assert.Equal(t, 50*time.Millisecond, cfg.InitialBackoff)
	assert.Equal(t, time.Minute, cfg.MaxBackoff)
	assert.InDelta(t, 0.1, cfg.JitterRatio, 0.001)
}

func TestNewRelay_NilLogger(t *testing.T) {
	// nil logger 应取默认；构造不 panic
	r := NewRelay(nil, nil, nil, RelayConfig{}, nil)
	assert.NotNil(t, r)
	assert.NotNil(t, r.logger)
}

func TestRun_NilDeps(t *testing.T) {
	r := NewRelay(nil, nil, nil, RelayConfig{}, nil)
	err := r.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "未初始化")
}
