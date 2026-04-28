package eventbus

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === 测试事件类型 ===

type AssetCreated struct {
	AssetID  string
	TenantID string
}

func (AssetCreated) Topic() string { return "asset.created.v1" }

type AssetDeleted struct {
	AssetID string
}

func (AssetDeleted) Topic() string { return "asset.deleted.v1" }

type TaskComplete struct {
	RunID string
}

func (TaskComplete) Topic() string { return "task.run.complete.v1" }

// === 基础 Subscribe + Publish ===

func TestPublishWithNoSubscribers(t *testing.T) {
	b := New(nil)
	err := Publish(context.Background(), b, AssetCreated{AssetID: "a"})
	assert.NoError(t, err, "无订阅者应静默成功")
}

func TestSubscribeAndPublish(t *testing.T) {
	b := New(nil)
	var got AssetCreated
	Subscribe[AssetCreated](b, func(_ context.Context, ev AssetCreated) error {
		got = ev
		return nil
	})

	require.NoError(t, Publish(context.Background(), b, AssetCreated{
		AssetID:  "ast_1",
		TenantID: "t_1",
	}))
	assert.Equal(t, "ast_1", got.AssetID)
	assert.Equal(t, "t_1", got.TenantID)
}

func TestMultipleHandlersSameTopic(t *testing.T) {
	b := New(nil)
	var calls []int
	var mu sync.Mutex

	for i := 0; i < 3; i++ {
		idx := i
		Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
			mu.Lock()
			calls = append(calls, idx)
			mu.Unlock()
			return nil
		})
	}

	require.NoError(t, Publish(context.Background(), b, AssetCreated{}))
	assert.Equal(t, []int{0, 1, 2}, calls, "handler 按注册顺序串行执行")
}

func TestDifferentTopicsIsolated(t *testing.T) {
	b := New(nil)
	var assetN, taskN atomic.Int32

	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		assetN.Add(1)
		return nil
	})
	Subscribe[TaskComplete](b, func(_ context.Context, _ TaskComplete) error {
		taskN.Add(1)
		return nil
	})

	require.NoError(t, Publish(context.Background(), b, AssetCreated{}))
	require.NoError(t, Publish(context.Background(), b, AssetCreated{}))
	require.NoError(t, Publish(context.Background(), b, TaskComplete{}))

	assert.Equal(t, int32(2), assetN.Load())
	assert.Equal(t, int32(1), taskN.Load())
}

// === ctx 透传 ===

type ctxKey struct{}

func TestContextPropagation(t *testing.T) {
	b := New(nil)
	var got string
	Subscribe[AssetCreated](b, func(ctx context.Context, _ AssetCreated) error {
		got, _ = ctx.Value(ctxKey{}).(string)
		return nil
	})

	ctx := context.WithValue(context.Background(), ctxKey{}, "request_id_xyz")
	require.NoError(t, Publish(ctx, b, AssetCreated{}))
	assert.Equal(t, "request_id_xyz", got)
}

// === error 处理 ===

func TestPublishReturnsFirstError(t *testing.T) {
	b := New(nil)
	calls := 0

	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		calls++
		return errors.New("first")
	})
	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		calls++
		return errors.New("second")
	})
	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		calls++
		return nil
	})

	err := Publish(context.Background(), b, AssetCreated{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "first")
	assert.Equal(t, 3, calls, "首个 error 不应短路；后续 handler 仍跑")
}

// === panic 恢复 ===

func TestHandlerPanicRecoveredAndOthersStillRun(t *testing.T) {
	b := New(nil)
	postPanicCalled := false

	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		panic("intentional test panic")
	})
	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		postPanicCalled = true
		return nil
	})

	err := Publish(context.Background(), b, AssetCreated{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "panic")
	assert.True(t, postPanicCalled, "panic 后续 handler 仍执行")
}

func TestHandlerPanicWithNonStringValue(t *testing.T) {
	b := New(nil)
	Subscribe[AssetCreated](b, func(_ context.Context, _ AssetCreated) error {
		panic(42) // 非 string panic
	})
	err := Publish(context.Background(), b, AssetCreated{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "42")
}

// === Topics / HandlerCount / Reset ===

func TestTopicsListed(t *testing.T) {
	b := New(nil)
	Subscribe[TaskComplete](b, func(context.Context, TaskComplete) error { return nil })
	Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error { return nil })
	Subscribe[AssetDeleted](b, func(context.Context, AssetDeleted) error { return nil })

	topics := b.Topics()
	assert.Equal(t, []string{
		"asset.created.v1",
		"asset.deleted.v1",
		"task.run.complete.v1",
	}, topics, "字典序")
}

func TestHandlerCount(t *testing.T) {
	b := New(nil)
	assert.Equal(t, 0, b.HandlerCount("asset.created.v1"))

	Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error { return nil })
	Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error { return nil })
	assert.Equal(t, 2, b.HandlerCount("asset.created.v1"))

	assert.Equal(t, 0, b.HandlerCount("nope.v1"))
}

func TestReset(t *testing.T) {
	b := New(nil)
	Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error { return nil })
	require.Equal(t, 1, b.HandlerCount("asset.created.v1"))

	b.Reset()
	assert.Equal(t, 0, b.HandlerCount("asset.created.v1"))
	assert.Empty(t, b.Topics())
}

// === nil-safe ===

func TestNilBusPublish(t *testing.T) {
	err := Publish(context.Background(), nil, AssetCreated{})
	require.Error(t, err)
}

func TestNilBusSubscribeNoOp(t *testing.T) {
	// 不应 panic
	Subscribe[AssetCreated](nil, func(context.Context, AssetCreated) error { return nil })
}

func TestNilHandlerSubscribeNoOp(t *testing.T) {
	b := New(nil)
	Subscribe[AssetCreated](b, nil)
	assert.Equal(t, 0, b.HandlerCount("asset.created.v1"))
}

func TestNilBusTopics(t *testing.T) {
	var b *Bus
	assert.Nil(t, b.Topics())
	assert.Equal(t, 0, b.HandlerCount("any"))
	b.Reset() // 不 panic
}

// === 并发 ===

func TestConcurrentSubscribePublish(t *testing.T) {
	b := New(nil)
	var subDone sync.WaitGroup
	subDone.Add(1)
	var subN, pubN atomic.Int32

	// 并发 Subscribe：固定 100 次（避免在快机器上 Subscribe 远快于 Publish，
	// 导致 handler 列表无界增长 + 每次 Publish 迭代上百万 handler 卡死）。
	go func() {
		defer subDone.Done()
		for i := 0; i < 100; i++ {
			Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error {
				return nil
			})
			subN.Add(1)
		}
	}()

	// 并发 Publish：固定 100 次。
	for i := 0; i < 100; i++ {
		_ = Publish(context.Background(), b, AssetCreated{AssetID: "x"})
		pubN.Add(1)
	}
	subDone.Wait()

	// race detector 必须干净（go test -race）；只确保循环跑了。
	assert.Equal(t, int32(100), pubN.Load())
	assert.Equal(t, int32(100), subN.Load())
}

// === 类型不匹配（防御）===
//
// 正常的泛型 Subscribe + Publish 不会出 mismatch（编译期保证）。
// 但 Subscribe 内部把 handler 擦除为 any，多个 topic 字符串相同但类型不同
// 时仍可能踩到。这种"两个不同的 Go 类型同 Topic 字串"是 LLD 20-eventbus
// 命名空间冲突错误，由代码评审防范。本包仅在运行时记日志。

// === 同一 Bus 多 publisher / 多 subscriber 互不影响 ===

func TestUnrelatedTopicsIndependence(t *testing.T) {
	b := New(nil)
	var assetCalled, taskCalled atomic.Int32

	Subscribe[AssetCreated](b, func(context.Context, AssetCreated) error {
		assetCalled.Add(1)
		return errors.New("asset failed")
	})
	Subscribe[TaskComplete](b, func(context.Context, TaskComplete) error {
		taskCalled.Add(1)
		return nil
	})

	// AssetCreated 失败不影响 TaskComplete
	require.Error(t, Publish(context.Background(), b, AssetCreated{}))
	require.NoError(t, Publish(context.Background(), b, TaskComplete{}))
	assert.Equal(t, int32(1), assetCalled.Load())
	assert.Equal(t, int32(1), taskCalled.Load())
}
