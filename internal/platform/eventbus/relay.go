package eventbus

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// RelayConfig Relay worker 行为参数。
type RelayConfig struct {
	// PollInterval 两次 outbox 扫描之间的间隔。默认 5s。
	PollInterval time.Duration

	// BatchSize 每次最多取多少条 pending 事件。默认 50。
	BatchSize int

	// MaxAttempts 一条事件最多尝试投递的次数。超出 → failed_permanently_at。默认 6。
	MaxAttempts int

	// InitialBackoff 第一次失败后的最小延迟。后续 attempts 按 2^n 倍增。默认 1s。
	InitialBackoff time.Duration

	// MaxBackoff 退避延迟上限。默认 5min。
	MaxBackoff time.Duration

	// JitterRatio 加在 backoff 上的抖动比例（0..1，例 0.2 = ±20%）。
	// 防多 Relay 同步重试雪崩。默认 0.2。
	JitterRatio float64
}

// Relay 是异步事件分发 worker。
//
// Run() 阻塞至 ctx.Done()；每 PollInterval 调一次 outbox.Pending → 通过 Registry
// 反序列化 + Bus.Publish 派发到 in-process handler。失败按指数退避 + jitter 重试，
// 超 MaxAttempts 标 failed_permanently_at。
type Relay struct {
	outbox   *Outbox
	bus      *Bus
	registry *Registry
	cfg      RelayConfig
	logger   *log.Logger
}

// NewRelay 构造 Relay；nil cfg 字段以默认填充。logger 为 nil 时取 log.Default()。
func NewRelay(o *Outbox, b *Bus, r *Registry, cfg RelayConfig, logger *log.Logger) *Relay {
	cfg = withRelayDefaults(cfg)
	if logger == nil {
		logger = log.Default()
	}
	return &Relay{
		outbox:   o,
		bus:      b,
		registry: r,
		cfg:      cfg,
		logger:   logger,
	}
}

// Run 启动轮询循环。返回 nil 当 ctx 取消（优雅退出）；返回 error 当不可恢复故障。
func (r *Relay) Run(ctx context.Context) error {
	if r == nil || r.outbox == nil || r.bus == nil || r.registry == nil {
		return errors.New("eventbus: Relay 未初始化（outbox / bus / registry 不能为 nil）")
	}
	r.logger.Info("relay starting",
		"poll_interval", r.cfg.PollInterval,
		"batch_size", r.cfg.BatchSize,
		"max_attempts", r.cfg.MaxAttempts,
	)
	ticker := time.NewTicker(r.cfg.PollInterval)
	defer ticker.Stop()

	// 进入 loop 前先跑一次，避免首次启动时延迟 PollInterval。
	r.processBatch(ctx)

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("relay stopping", "reason", ctx.Err().Error())
			return nil
		case <-ticker.C:
			r.processBatch(ctx)
		}
	}
}

// processBatch 取一批 pending → 逐个 dispatch + 标记结果。
func (r *Relay) processBatch(ctx context.Context) {
	records, err := r.outbox.Pending(ctx, r.cfg.BatchSize)
	if err != nil {
		r.logger.LogError(ctx, "relay: pending query failed", err)
		return
	}
	if len(records) == 0 {
		return
	}
	for _, rec := range records {
		if ctx.Err() != nil {
			return // ctx 已取消，不再处理后续
		}
		r.processOne(ctx, rec)
	}
}

// processOne 处理单条记录：dispatch → 标记。失败时按 attempts 退避或永久失败。
func (r *Relay) processOne(ctx context.Context, rec Record) {
	dispatchErr := r.registry.Dispatch(ctx, r.bus, rec.Topic, rec.Payload)
	if dispatchErr == nil {
		if err := r.outbox.MarkPublished(ctx, rec.ID); err != nil {
			// 已成功 dispatch 但更新表失败 → 下一轮会重投
			// （handler 应保证幂等，这是 at-least-once 语义的代价）
			r.logger.LogError(ctx, "relay: mark published failed", err,
				"id", rec.ID, "topic", rec.Topic)
		}
		return
	}

	nextAttempts := rec.Attempts + 1
	permanent := nextAttempts >= r.cfg.MaxAttempts
	delay := r.computeBackoff(nextAttempts)

	r.logger.Warn("relay: dispatch failed",
		"id", rec.ID,
		"topic", rec.Topic,
		"attempt", nextAttempts,
		"max_attempts", r.cfg.MaxAttempts,
		"permanent", permanent,
		"next_delay_ms", delay.Milliseconds(),
		"error", dispatchErr.Error(),
	)

	if err := r.outbox.MarkFailed(ctx, rec.ID, dispatchErr.Error(), delay, permanent); err != nil {
		r.logger.LogError(ctx, "relay: mark failed failed", err,
			"id", rec.ID, "topic", rec.Topic)
	}
}

// computeBackoff 指数退避 + jitter。
// attempt=1 → InitialBackoff，attempt=N → InitialBackoff * 2^(N-1)，封顶 MaxBackoff。
// 然后加 ±JitterRatio 范围抖动。
func (r *Relay) computeBackoff(attempt int) time.Duration {
	base := r.cfg.InitialBackoff
	for i := 1; i < attempt && base < r.cfg.MaxBackoff; i++ {
		base *= 2
	}
	if base > r.cfg.MaxBackoff {
		base = r.cfg.MaxBackoff
	}
	if r.cfg.JitterRatio > 0 {
		// jitter ∈ [-jitterRatio, +jitterRatio] * base
		j := (rand.Float64()*2 - 1) * r.cfg.JitterRatio //nolint:gosec // jitter 不需密码学随机
		base = time.Duration(float64(base) * (1 + j))
	}
	if base < 0 {
		base = 0
	}
	return base
}

const (
	defaultPollInterval   = 5 * time.Second
	defaultBatchSize      = 50
	defaultMaxAttempts    = 6
	defaultInitialBackoff = 1 * time.Second
	defaultMaxBackoff     = 5 * time.Minute
	defaultJitterRatio    = 0.2
)

func withRelayDefaults(cfg RelayConfig) RelayConfig {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultPollInterval
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaultBatchSize
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultMaxAttempts
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.JitterRatio < 0 {
		cfg.JitterRatio = 0
	}
	if cfg.JitterRatio == 0 {
		cfg.JitterRatio = defaultJitterRatio
	}
	return cfg
}
