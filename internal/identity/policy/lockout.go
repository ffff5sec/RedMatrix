// Package policy 是 identity 模块的策略层（lockout / captcha / 密码强度等）。
//
// LLD 10 §4.5：失败计数与锁定，账号 + IP 双维度独立计算（D-18），Redis 故障 fail-open（D-19）。
//
// Redis Key（LLD 01 §3.2）：
//
//	global:auth:failures:account:{user_id}   ZSet  失败时间窗口
//	global:auth:failures:ip:{ip}             ZSet  同上
//	global:auth:lockout:account:{user_id}    String 锁定标记，值=解锁 unix_ts
//	global:auth:lockout:ip:{ip}              String 同上
package policy

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Config 是 lockout 策略参数（LLD 04 §3.1 security.lockout）。
//
// 默认值（DefaultConfig）来自 LLD：
//   - 账号 5 次 / 10 分钟窗口 → 锁 15 分钟
//   - IP 20 次 / 1 分钟窗口 → 锁 60 分钟
type Config struct {
	AccountThreshold      int
	AccountWindow         time.Duration
	AccountLockoutFor     time.Duration
	IPThreshold           int
	IPWindow              time.Duration
	IPLockoutFor          time.Duration
	FailureRetentionExtra time.Duration // ZSet TTL = window + extra（防 key 残留）
}

// DefaultConfig 来自 LLD 10 §4.5。
func DefaultConfig() Config {
	return Config{
		AccountThreshold:      5,
		AccountWindow:         10 * time.Minute,
		AccountLockoutFor:     15 * time.Minute,
		IPThreshold:           20,
		IPWindow:              1 * time.Minute,
		IPLockoutFor:          60 * time.Minute,
		FailureRetentionExtra: 10 * time.Minute,
	}
}

// Validate 检查配置合法性；阈值 / 时长必须 > 0。
func (c Config) Validate() error {
	if c.AccountThreshold <= 0 || c.IPThreshold <= 0 {
		return errx.New(errx.ErrInvalidInput, "lockout: 阈值必须 > 0")
	}
	if c.AccountWindow <= 0 || c.IPWindow <= 0 ||
		c.AccountLockoutFor <= 0 || c.IPLockoutFor <= 0 {
		return errx.New(errx.ErrInvalidInput, "lockout: 时长必须 > 0")
	}
	return nil
}

// Lockout 是策略层接口。AuthService 在 Login 流程里调用。
type Lockout interface {
	// IsIPLocked 查 IP 是否已锁定；fail-open（Redis 故障返 false）。
	IsIPLocked(ctx context.Context, ip netip.Addr) (locked bool, until time.Time)

	// IsAccountLocked 查账号是否已锁定；fail-open。
	IsAccountLocked(ctx context.Context, userID string) (locked bool, until time.Time)

	// RecordFailure 失败 +1（账号 + IP 两个维度）；窗口内累积 ≥ 阈值时触发锁定。
	// 返回 (justLockedAccount, justLockedIP)：caller 据此发布 auth.lockout.triggered 事件。
	RecordFailure(ctx context.Context, ip netip.Addr, userID string) (acctLocked, ipLocked bool)

	// ResetFailures 成功登录后清账号 + IP 维度的失败计数（不清 lockout——它有 EXPIRE）。
	ResetFailures(ctx context.Context, ip netip.Addr, userID string)
}

// === Redis 实现 ===

// Key 名前缀；与 LLD 01 §3.2 对齐。
const (
	keyFailureAccountPrefix = "global:auth:failures:account:"
	keyFailureIPPrefix      = "global:auth:failures:ip:"
	keyLockoutAccountPrefix = "global:auth:lockout:account:"
	keyLockoutIPPrefix      = "global:auth:lockout:ip:"
)

// redisLockout 用 go-redis 实现 Lockout。
type redisLockout struct {
	client redis.Cmdable
	cfg    Config
	now    func() time.Time
}

// NewRedis 构造 Redis-backed Lockout。
func NewRedis(client redis.Cmdable, cfg Config) (Lockout, error) {
	if client == nil {
		return nil, errx.New(errx.ErrInvalidInput, "policy.NewRedis: client 不能为 nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &redisLockout{
		client: client,
		cfg:    cfg,
		now:    time.Now,
	}, nil
}

// === IsLocked ===

func (l *redisLockout) IsIPLocked(ctx context.Context, ip netip.Addr) (bool, time.Time) {
	if !ip.IsValid() {
		return false, time.Time{}
	}
	return l.isLocked(ctx, keyLockoutIPPrefix+ip.String())
}

func (l *redisLockout) IsAccountLocked(ctx context.Context, userID string) (bool, time.Time) {
	if userID == "" {
		return false, time.Time{}
	}
	return l.isLocked(ctx, keyLockoutAccountPrefix+userID)
}

// isLocked GET key；存在 + 解析为 unix_ts → (true, 解锁时间)；故障/不存在 → (false, _)。
func (l *redisLockout) isLocked(ctx context.Context, key string) (bool, time.Time) {
	v, err := l.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return false, time.Time{}
	}
	if err != nil {
		// fail-open（D-19）
		return false, time.Time{}
	}
	ts, perr := strconv.ParseInt(v, 10, 64)
	if perr != nil {
		return false, time.Time{}
	}
	until := time.Unix(ts, 0)
	if l.now().After(until) {
		// 已过期但 key 还在（极少见 race）；fail-open
		return false, time.Time{}
	}
	return true, until
}

// === RecordFailure ===

func (l *redisLockout) RecordFailure(ctx context.Context, ip netip.Addr, userID string) (bool, bool) {
	now := l.now()
	acctLocked := false
	ipLocked := false

	if userID != "" {
		acctLocked = l.recordOne(ctx,
			keyFailureAccountPrefix+userID,
			keyLockoutAccountPrefix+userID,
			l.cfg.AccountThreshold, l.cfg.AccountWindow, l.cfg.AccountLockoutFor, now)
	}
	if ip.IsValid() {
		ipLocked = l.recordOne(ctx,
			keyFailureIPPrefix+ip.String(),
			keyLockoutIPPrefix+ip.String(),
			l.cfg.IPThreshold, l.cfg.IPWindow, l.cfg.IPLockoutFor, now)
	}
	return acctLocked, ipLocked
}

// recordOne 单维度失败处理；返回是否本次触发新锁定。
//
// pipeline:
//  1. ZRemRangeByScore failKey -inf, now-window  // 清窗外
//  2. ZAdd failKey {score=now, member=uuid}      // 计入本次
//  3. Expire failKey window+extra                // key TTL 兜底
//  4. ZCard failKey                              // 当前窗内失败数
//
// ≥ 阈值 → SET lockKey unlock_ts EX lockoutFor。fail-open：任何 Redis 错都返 false。
func (l *redisLockout) recordOne(
	ctx context.Context,
	failKey, lockKey string,
	threshold int,
	window, lockoutFor time.Duration,
	now time.Time,
) bool {
	pipe := l.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, failKey, "-inf",
		strconv.FormatInt(now.Add(-window).Unix(), 10))
	pipe.ZAdd(ctx, failKey, redis.Z{
		Score:  float64(now.Unix()),
		Member: uuid.NewString(),
	})
	pipe.Expire(ctx, failKey, window+l.cfg.FailureRetentionExtra)
	cardCmd := pipe.ZCard(ctx, failKey)
	if _, err := pipe.Exec(ctx); err != nil {
		return false
	}
	count := int(cardCmd.Val())
	if count < threshold {
		return false
	}
	// 触发锁定：SET lockKey unlock_at EX lockoutFor
	until := now.Add(lockoutFor)
	if err := l.client.Set(ctx, lockKey,
		strconv.FormatInt(until.Unix(), 10),
		lockoutFor).Err(); err != nil {
		return false
	}
	return true
}

// === ResetFailures ===

func (l *redisLockout) ResetFailures(ctx context.Context, ip netip.Addr, userID string) {
	keys := make([]string, 0, 2)
	if userID != "" {
		keys = append(keys, keyFailureAccountPrefix+userID)
	}
	if ip.IsValid() {
		keys = append(keys, keyFailureIPPrefix+ip.String())
	}
	if len(keys) == 0 {
		return
	}
	// 不清 lockout key — 它有 EXPIRE 自动过期；管理员强制解锁是单独 RPC（后续 PR）。
	if err := l.client.Del(ctx, keys...).Err(); err != nil {
		// fail-open
		_ = err
	}
}
