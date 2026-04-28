// Package eventbus 是 RedMatrix 后端的进程内同步事件总线（Sync 层）。
//
// 双层架构（docs/LLD/20-eventbus-impl.md）：
//
//	┌───────────────┐    Sync (本包)         ┌───────────────────┐
//	│  Publisher    │ ────同步分发──────────►│ in-process Handler │
//	└───────────────┘                        └───────────────────┘
//
//	┌───────────────┐ Async (待落)  ┌────────┐  ┌──────────┐  ┌─────────┐
//	│ PublishTx(tx) │──── outbox ──►│ PG Tx  │─►│ Redis    │─►│ Relay   │
//	└───────────────┘   AfterCommit │ commit │  │ Streams  │  │ workers │
//	                                └────────┘  └──────────┘  └─────────┘
//
// 设计要点：
//   - 事件类型必须实现 Event 接口（Topic() string）；约定 Topic 是常量字串。
//   - Subscribe / Publish 是泛型函数，不是 *Bus 方法（Go 1.18+ 不支持方法泛型）。
//   - 一个 topic 可注册多个 handler；按注册顺序串行执行。
//   - handler panic 被恢复 + 记录日志，不阻塞其他 handler。
//   - handler 返回 error 时，Publish 返回首个 error；其余 handler 仍执行。
//   - Publish 在调用方 goroutine 同步运行（保留 ctx / 顺序语义）。
//
// Async 层（Outbox + Relay + Redis Streams）由后续 PR 实现，与本包通过
// PublishTx 接口（待添加）联动。
package eventbus

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// Event 是任意"可被分发"的类型必须实现的接口。
//
// 约定：Topic() 返回常量字串（不依赖字段），形如
// "asset.created.v1" / "task.run.complete.v1" / "user.login.v1"。
// 这样 var zero T 的 zero.Topic() 也能正确返回（Subscribe 时取 topic 用）。
type Event interface {
	Topic() string
}

// Handler 是 topic T 的处理函数。
type Handler[T Event] func(ctx context.Context, ev T) error

// Bus 是进程内同步事件总线。零值不可用；用 New 构造。
type Bus struct {
	mu       sync.RWMutex
	handlers map[string][]erasedHandler // topic → handler 列表
	logger   *log.Logger
}

// erasedHandler 是消除泛型后的 handler 表示，便于按 topic 字符串聚合。
type erasedHandler struct {
	// invoke 接受 any 类型 event，内部 type-assert 回原 T。
	invoke func(ctx context.Context, ev any) error

	// expected 是 handler 期望的具体类型（仅用于 mismatch 错误信息）。
	expected string
}

// New 构造 Bus。logger 为 nil 时取 log.Default()。
func New(logger *log.Logger) *Bus {
	if logger == nil {
		logger = log.Default()
	}
	return &Bus{
		handlers: make(map[string][]erasedHandler),
		logger:   logger,
	}
}

// Subscribe 把 handler 注册到事件类型 T 对应的 topic 上。
//
// Topic 在注册时通过 var zero T; zero.Topic() 解析；故 T 的 Topic 实现
// 不能访问字段（约定常量返回）。同一 topic 多次 Subscribe 累加，按注册顺序
// 在 Publish 时串行执行。
func Subscribe[T Event](b *Bus, h Handler[T]) {
	if b == nil || h == nil {
		return
	}
	var zero T
	topic := zero.Topic()

	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[topic] = append(b.handlers[topic], erasedHandler{
		expected: fmt.Sprintf("%T", zero),
		invoke: func(ctx context.Context, ev any) error {
			typed, ok := ev.(T)
			if !ok {
				return fmt.Errorf("eventbus: handler type mismatch (want %T, got %T)", zero, ev)
			}
			return h(ctx, typed)
		},
	})
}

// Publish 同步分发 ev 到所有已注册 handler。
//
//   - 0 个订阅者 → 静默返回 nil（"fire and forget" 风格）
//   - handler 返回 error → 记录到首个非 nil；其余 handler 仍执行
//   - handler panic → 恢复 + 日志 + 记为该 handler 的 error，下个 handler 继续
//
// 调用 goroutine 同步运行；ctx 透传给所有 handler。
func Publish[T Event](ctx context.Context, b *Bus, ev T) error {
	if b == nil {
		return errors.New("eventbus: nil Bus")
	}
	topic := ev.Topic()

	b.mu.RLock()
	// 拷贝 slice 避免在执行期被并发 Subscribe 修改影响。
	hs := append([]erasedHandler(nil), b.handlers[topic]...)
	b.mu.RUnlock()

	var firstErr error
	for i, h := range hs {
		if err := safeInvoke(ctx, h, ev, b.logger, topic, i); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// safeInvoke 用 defer/recover 包装 handler.invoke。panic 被转为 error 返回。
func safeInvoke(ctx context.Context, h erasedHandler, ev any, logger *log.Logger, topic string, idx int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("eventbus: handler panic: %v", r)
			if logger != nil {
				logger.Error("eventbus handler panic recovered",
					"topic", topic,
					"handler_idx", idx,
					"panic", fmt.Sprintf("%v", r),
				)
			}
		}
	}()
	return h.invoke(ctx, ev)
}

// Topics 列出所有已注册 topic（按字典序）。诊断与调试用。
func (b *Bus) Topics() []string {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	out := make([]string, 0, len(b.handlers))
	for k := range b.handlers {
		out = append(out, k)
	}
	b.mu.RUnlock()
	// stable order
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// HandlerCount 返回指定 topic 的 handler 数（用于测试与监控）。
func (b *Bus) HandlerCount(topic string) int {
	if b == nil {
		return 0
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.handlers[topic])
}

// Reset 清空所有 handler（仅供测试 / 进程重启路径用）。
func (b *Bus) Reset() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.handlers = make(map[string][]erasedHandler)
	b.mu.Unlock()
}
