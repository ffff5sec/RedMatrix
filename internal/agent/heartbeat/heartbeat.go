// Package heartbeat 跑 Agent 端的周期 Heartbeat 循环。
//
// 行为：
//   - 间隔由首次 Heartbeat 返回的 IntervalSeconds 决定，缺省 30s
//   - 叠 ±10% jitter 防雪崩
//   - ctx 取消 → 退出循环
//   - 调用失败仅日志（不退出，让 last_seen_at 自然过期触发服务端 offline）
package heartbeat

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand"
	"time"

	"connectrpc.com/connect"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
)

// DefaultInterval 是 server 未告知 next interval 时本地兜底值。
const DefaultInterval = 30 * time.Second

// Logger 是本包用的最小日志接口；让 cmd/node 注入任意 logger。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// noopLogger 仅用作默认；不写任何东西。
type noopLogger struct{}

func (noopLogger) Info(string, ...any) {}
func (noopLogger) Warn(string, ...any) {}

// Loop 跑心跳循环；ctx 退出后返 ctx.Err()（context.Canceled / DeadlineExceeded）。
//
// 第一次发请求是同步的——失败会直接返；让 caller 早发现配置 / 网络问题。
type Loop struct {
	Client  tenancyv1connect.NodeAgentServiceClient
	Version string // Agent 自报版本
	Logger  Logger // 可空：用 noop
	Rand    *mathrand.Rand
	Now     func() time.Time
}

// Run 阻塞跑直到 ctx 取消。返 ctx.Err()。
func (l *Loop) Run(ctx context.Context) error {
	if l == nil || l.Client == nil {
		return errors.New("heartbeat: Loop 依赖未装齐")
	}
	logger := l.Logger
	if logger == nil {
		logger = noopLogger{}
	}
	rng := l.Rand
	if rng == nil {
		rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano())) //nolint:gosec // 仅 jitter 用，无安全语义
	}

	interval := DefaultInterval
	// 首发：失败让 caller 退出（早期诊断）
	first, err := l.beat(ctx)
	if err != nil {
		return fmt.Errorf("heartbeat: 首次失败: %w", err)
	}
	if first > 0 {
		interval = first
	}
	logger.Info("heartbeat: first beat ok", "interval", interval.String())

	timer := time.NewTimer(jitter(interval, rng))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			next, err := l.beat(ctx)
			if err != nil {
				logger.Warn("heartbeat failed", "err", err.Error())
			} else if next > 0 && next != interval {
				logger.Info("heartbeat interval updated", "old", interval, "new", next)
				interval = next
			}
			timer.Reset(jitter(interval, rng))
		}
	}
}

// beat 发一次 Heartbeat；返 server 期望下次间隔（0 = 用本地默认）。
func (l *Loop) beat(ctx context.Context) (time.Duration, error) {
	res, err := l.Client.Heartbeat(ctx, connect.NewRequest(&tenancyv1.HeartbeatRequest{
		Version: l.Version,
	}))
	if err != nil {
		return 0, err
	}
	if res.Msg == nil {
		return 0, errors.New("heartbeat: empty response")
	}
	return time.Duration(res.Msg.GetIntervalSeconds()) * time.Second, nil
}

// jitter 返 base ± 10%；用 rng 而非 rand.Int63 让测试稳定。
func jitter(base time.Duration, rng *mathrand.Rand) time.Duration {
	if base <= 0 {
		return DefaultInterval
	}
	delta := time.Duration(rng.Int63n(int64(base) / 5)) // [0, 20%]
	return base - base/10 + delta                       // base - 10% + [0, 20%] = base ± 10%
}
