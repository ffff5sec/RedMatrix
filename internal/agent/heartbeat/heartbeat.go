// Package heartbeat 跑 Agent 端的周期 Heartbeat 循环。
//
// 行为：
//   - 间隔由首次 Heartbeat 返回的 IntervalSeconds 决定，缺省 30s
//   - 叠 ±10% jitter 防雪崩
//   - ctx 取消 → 退出循环
//   - 调用失败仅日志（不退出，让 last_seen_at 自然过期触发服务端 offline）
//
// PR-T4-D5：每次 beat 完检查当前 cert 距过期时长 ≤ RenewBefore 时
// 触发 ReissueCert + store.Save + 替换 mTLS client（不退出循环）。
package heartbeat

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	mathrand "math/rand"
	"time"

	"connectrpc.com/connect"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
)

// DefaultInterval 是 server 未告知 next interval 时本地兜底值。
const DefaultInterval = 30 * time.Second

// DefaultRenewBefore 默认续期阈值：cert NotAfter - now ≤ 7 天 → 触发 ReissueCert。
//
// 服务端默认签 30 天 cert，留 7 天窗口；agent 30s/次心跳，最早 23 天后开始续。
const DefaultRenewBefore = 7 * 24 * time.Hour

// Logger 是本包用的最小日志接口；让 cmd/node 注入任意 logger。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// noopLogger 仅用作默认；不写任何东西。
type noopLogger struct{}

func (noopLogger) Info(string, ...any) {}
func (noopLogger) Warn(string, ...any) {}

// RebuildClientFunc 用新 enrollment 重建 mTLS client（cmd/node 注入；
// 让 heartbeat 包不感知 connect / tls 装配细节）。
type RebuildClientFunc func(*store.Enrollment) (tenancyv1connect.NodeAgentServiceClient, error)

// Loop 跑心跳循环；ctx 退出后返 ctx.Err()（context.Canceled / DeadlineExceeded）。
//
// 第一次发请求是同步的——失败会直接返；让 caller 早发现配置 / 网络问题。
type Loop struct {
	Client  tenancyv1connect.NodeAgentServiceClient
	Version string // Agent 自报版本
	Logger  Logger // 可空：用 noop
	Rand    *mathrand.Rand
	Now     func() time.Time

	// === PR-T4-D5：cert 续期能力（可空，nil 字段任意一个 → 不续）===

	// Store 用于持久新 enrollment（cert / key / ca / node-id）。
	Store *store.Store
	// Enrollment 当前 enrollment；Loop 需要解析其 CertPEM 拿 NotAfter。
	Enrollment *store.Enrollment
	// RenewBefore cert NotAfter - now ≤ 此值时触发续期；0 = 不续。
	RenewBefore time.Duration
	// RebuildClient 用新 enrollment 装新 mTLS client；返 nil 直接错跳。
	RebuildClient RebuildClientFunc
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
	now := l.Now
	if now == nil {
		now = time.Now
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

	// 首发后立即检查一次续期（避免漏掉刚启动就临过期的极端情况）
	l.maybeRenew(ctx, logger, now)

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
			l.maybeRenew(ctx, logger, now)
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

// maybeRenew 检查当前 cert 是否临过期，是 → 调 ReissueCert + 持久 + 换 client。
//
// 续期失败仅日志（保持心跳循环不退出）；下一次 beat 后再试。
func (l *Loop) maybeRenew(ctx context.Context, logger Logger, now func() time.Time) {
	if !l.canRenew() {
		return
	}
	expiresAt, err := certNotAfter(l.Enrollment.CertPEM)
	if err != nil {
		logger.Warn("renew: 解析 cert NotAfter 失败", "err", err.Error())
		return
	}
	remaining := expiresAt.Sub(now())
	if remaining > l.RenewBefore {
		return
	}
	logger.Info("renew: cert 临过期，触发 ReissueCert",
		"remaining", remaining.String(),
		"renew_before", l.RenewBefore.String(),
	)
	if err := l.renew(ctx); err != nil {
		logger.Warn("renew failed", "err", err.Error())
		return
	}
	newExpire, _ := certNotAfter(l.Enrollment.CertPEM)
	logger.Info("renew: cert 已续期",
		"new_expires_at", newExpire.UTC().Format(time.RFC3339),
		"new_fingerprint_short", shortFP(l.Enrollment),
	)
}

// canRenew 判定续期能力是否就绪（任一字段缺失 → false）。
func (l *Loop) canRenew() bool {
	return l.RenewBefore > 0 &&
		l.Store != nil &&
		l.Enrollment != nil &&
		len(l.Enrollment.CertPEM) > 0 &&
		l.RebuildClient != nil
}

// renew 执行 ReissueCert → 落盘 → 换 client。失败时不修改 Loop 状态。
func (l *Loop) renew(ctx context.Context) error {
	res, err := l.Client.ReissueCert(ctx, connect.NewRequest(&tenancyv1.ReissueCertRequest{}))
	if err != nil {
		return fmt.Errorf("ReissueCert RPC: %w", err)
	}
	if res.Msg == nil ||
		res.Msg.GetNodeCertPem() == "" ||
		res.Msg.GetNodeKeyPem() == "" ||
		res.Msg.GetCaCertPem() == "" {
		return errors.New("ReissueCert: server 返回空 PEM")
	}
	newEnroll := &store.Enrollment{
		NodeID:    l.Enrollment.NodeID, // 不变
		CertPEM:   []byte(res.Msg.GetNodeCertPem()),
		KeyPEM:    []byte(res.Msg.GetNodeKeyPem()),
		CACertPEM: []byte(res.Msg.GetCaCertPem()),
	}
	if err := l.Store.Save(newEnroll); err != nil {
		return fmt.Errorf("save 新 enrollment: %w", err)
	}
	newClient, err := l.RebuildClient(newEnroll)
	if err != nil {
		return fmt.Errorf("rebuild mTLS client: %w", err)
	}
	l.Client = newClient
	l.Enrollment = newEnroll
	return nil
}

// certNotAfter 从 PEM 字串解 leaf cert 拿 NotAfter；多 cert 只看第一个。
func certNotAfter(pemBytes []byte) (time.Time, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return time.Time{}, errors.New("cert PEM 解码失败")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("ParseCertificate: %w", err)
	}
	return leaf.NotAfter, nil
}

// shortFP 取 enrollment 的 cert 指纹前 12 位用于日志（safe；非敏感）。
func shortFP(e *store.Enrollment) string {
	if e == nil || len(e.CertPEM) == 0 {
		return ""
	}
	block, _ := pem.Decode(e.CertPEM)
	if block == nil {
		return ""
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	// SHA-256 of leaf.Raw 太麻烦——用 SerialNumber 前若干位代替（同 cert 切换可见）
	sn := leaf.SerialNumber.String()
	if len(sn) > 12 {
		return sn[:12]
	}
	return sn
}

// jitter 返 base ± 10%；用 rng 而非 rand.Int63 让测试稳定。
func jitter(base time.Duration, rng *mathrand.Rand) time.Duration {
	if base <= 0 {
		return DefaultInterval
	}
	delta := time.Duration(rng.Int63n(int64(base) / 5)) // [0, 20%]
	return base - base/10 + delta                       // base - 10% + [0, 20%] = base ± 10%
}
