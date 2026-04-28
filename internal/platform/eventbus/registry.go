package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Registry 把 topic 字串映射到能"反序列化 + 派发"的闭包。
//
// Relay 从 outbox 读到 (topic string, payload []byte) 后，必须借助 Registry
// 知道用哪个 Go 类型 unmarshal —— 否则无法调 Subscribe[T] 注册的 typed handler。
//
// 用法（每模块在 init / boot 注册一次）：
//
//	registry := eventbus.NewRegistry()
//	eventbus.RegisterType[AssetCreated](registry)
//	eventbus.RegisterType[TaskComplete](registry)
//
// 同 topic 重复注册会替换，但更换"承载类型"是错误（一个 topic 只能对应一个 Go 类型）；
// 调用方约定保证（生产代码每个 topic 类型一对一）。
type Registry struct {
	mu          sync.RWMutex
	dispatchers map[string]dispatcher
}

// dispatcher 是一个 topic 专属的"反序列化 + Publish"闭包。
type dispatcher func(ctx context.Context, bus *Bus, payload []byte) error

// NewRegistry 创建空 Registry。
func NewRegistry() *Registry {
	return &Registry{
		dispatchers: make(map[string]dispatcher),
	}
}

// RegisterType 把类型 T 的 Topic() 注册到 r。
//
// 闭包内部：
//  1. var ev T
//  2. json.Unmarshal(payload, &ev)
//  3. Publish(ctx, bus, ev)
//
// 这种"在注册时捕获泛型 T"的模式让 Relay 在运行时（已经丢失 T）也能派发回 Subscribe[T]。
func RegisterType[T Event](r *Registry) {
	if r == nil {
		return
	}
	var zero T
	topic := zero.Topic()
	r.mu.Lock()
	r.dispatchers[topic] = func(ctx context.Context, bus *Bus, payload []byte) error {
		var ev T
		if err := json.Unmarshal(payload, &ev); err != nil {
			return errx.Wrap(errx.ErrInternal, err,
				fmt.Sprintf("eventbus: unmarshal %s payload", topic)).
				WithFields("topic", topic)
		}
		return Publish(ctx, bus, ev)
	}
	r.mu.Unlock()
}

// Dispatch 反序列化 payload 并通过 bus 同步派发。
//
//   - topic 未注册 → 返回 *errx.DomainError(ErrInternal)
//   - JSON 反序列化失败 → 同上
//   - bus.Publish 返回的首个 error 透传
func (r *Registry) Dispatch(ctx context.Context, bus *Bus, topic string, payload []byte) error {
	if r == nil {
		return errx.New(errx.ErrInternal, "eventbus: nil Registry")
	}
	r.mu.RLock()
	d, ok := r.dispatchers[topic]
	r.mu.RUnlock()
	if !ok {
		return errx.New(errx.ErrInternal,
			fmt.Sprintf("eventbus: unknown topic %q（未在 Registry 注册）", topic)).
			WithFields("topic", topic)
	}
	return d(ctx, bus, payload)
}

// Topics 列出所有已注册 topic（字典序）。
func (r *Registry) Topics() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]string, 0, len(r.dispatchers))
	for k := range r.dispatchers {
		out = append(out, k)
	}
	r.mu.RUnlock()
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
