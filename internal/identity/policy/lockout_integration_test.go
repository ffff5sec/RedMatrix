//go:build integration

package policy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rmredis "github.com/ffff5sec/RedMatrix/internal/storage/redis"
	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

const testUserID = "11111111-1111-1111-1111-111111111111"

func setupLockout(t *testing.T) (Lockout, *redis.Client) {
	t.Helper()
	h := redisharness.Start(t)

	c, err := rmredis.Open(context.Background(), rmredis.Config{URL: h.URL})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	require.NoError(t, c.Ping(context.Background()))

	cfg := DefaultConfig()
	// 缩小窗口便于测试
	cfg.AccountThreshold = 3
	cfg.AccountWindow = 30 * time.Second
	cfg.AccountLockoutFor = 10 * time.Second
	cfg.IPThreshold = 5
	cfg.IPWindow = 30 * time.Second
	cfg.IPLockoutFor = 10 * time.Second

	l, err := NewRedis(c.Client, cfg)
	require.NoError(t, err)
	return l, c.Client
}

// === IsLocked 初始 false ===

func TestIsAccountLocked_Initial(t *testing.T) {
	l, _ := setupLockout(t)
	locked, _ := l.IsAccountLocked(context.Background(), testUserID)
	assert.False(t, locked)
}

func TestIsIPLocked_Initial(t *testing.T) {
	l, _ := setupLockout(t)
	locked, _ := l.IsIPLocked(context.Background(),
		netip.MustParseAddr("203.0.113.42"))
	assert.False(t, locked)
}

func TestIsLocked_InvalidIP_FailOpen(t *testing.T) {
	l, _ := setupLockout(t)
	locked, _ := l.IsIPLocked(context.Background(), netip.Addr{})
	assert.False(t, locked, "无效 IP 直接返 false（不查 Redis）")
}

func TestIsLocked_EmptyUserID_FailOpen(t *testing.T) {
	l, _ := setupLockout(t)
	locked, _ := l.IsAccountLocked(context.Background(), "")
	assert.False(t, locked)
}

// === RecordFailure 累计触发锁定 ===

func TestRecordFailure_LocksAccountAtThreshold(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.42")

	// 头 2 次：未达阈值
	for i := 0; i < 2; i++ {
		acct, _ := l.RecordFailure(ctx, ip, testUserID)
		assert.False(t, acct, "第 %d 次不应锁定", i+1)
	}
	// 第 3 次：达阈值（cfg.AccountThreshold = 3）
	acct, _ := l.RecordFailure(ctx, ip, testUserID)
	assert.True(t, acct, "第 3 次应锁定账号")

	// IsAccountLocked 应反映
	locked, until := l.IsAccountLocked(ctx, testUserID)
	require.True(t, locked)
	assert.WithinDuration(t, time.Now().Add(10*time.Second), until, 2*time.Second)
}

func TestRecordFailure_LocksIPAtThreshold(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.99")

	// IP 阈值 5；用 5 个不同 user 触发（避免账号先锁）
	for i := 0; i < 4; i++ {
		_, ipL := l.RecordFailure(ctx, ip,
			"22222222-2222-2222-2222-22222222222"+string(rune('0'+i)))
		assert.False(t, ipL, "第 %d 次 IP 不应锁定", i+1)
	}
	_, ipL := l.RecordFailure(ctx, ip,
		"22222222-2222-2222-2222-222222222224")
	assert.True(t, ipL, "第 5 次 IP 应锁定")

	locked, _ := l.IsIPLocked(ctx, ip)
	assert.True(t, locked)
}

func TestRecordFailure_AccountAndIPIndependent(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.50")

	// 账号触发锁（3 次同 user）
	for i := 0; i < 3; i++ {
		_, _ = l.RecordFailure(ctx, ip, testUserID)
	}
	acctLocked, _ := l.IsAccountLocked(ctx, testUserID)
	ipLocked, _ := l.IsIPLocked(ctx, ip)
	assert.True(t, acctLocked, "账号锁定")
	assert.False(t, ipLocked, "IP 阈值 5，3 次未到")
}

func TestRecordFailure_NoUserID_OnlyIP(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.51")

	// userID="" 时只跑 IP 维度
	for i := 0; i < 5; i++ {
		acct, ipL := l.RecordFailure(ctx, ip, "")
		assert.False(t, acct, "userID 空不应触发账号锁")
		if i < 4 {
			assert.False(t, ipL)
		} else {
			assert.True(t, ipL, "第 5 次 IP 应锁定")
		}
	}
}

func TestRecordFailure_InvalidIP_OnlyAccount(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		acct, ipL := l.RecordFailure(ctx, netip.Addr{}, testUserID)
		assert.False(t, ipL, "无效 IP 不应记 IP 维度")
		if i < 2 {
			assert.False(t, acct)
		} else {
			assert.True(t, acct, "第 3 次账号应锁定")
		}
	}
}

// === ResetFailures 清计数 ===

func TestResetFailures_ClearsCounters(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.55")

	// 累 2 次
	_, _ = l.RecordFailure(ctx, ip, testUserID)
	_, _ = l.RecordFailure(ctx, ip, testUserID)

	// 重置
	l.ResetFailures(ctx, ip, testUserID)

	// 重置后再发 2 次仍未锁定（如果计数没清，第 1 次就会因为已经累 2 次直接到 3 触发锁）
	acct, _ := l.RecordFailure(ctx, ip, testUserID)
	assert.False(t, acct)
	acct, _ = l.RecordFailure(ctx, ip, testUserID)
	assert.False(t, acct, "Reset 后计数清零；新 2 次仍 < 3")
}

func TestResetFailures_DoesNotClearLockout(t *testing.T) {
	l, _ := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.56")

	// 触发锁定
	for i := 0; i < 3; i++ {
		_, _ = l.RecordFailure(ctx, ip, testUserID)
	}
	locked, _ := l.IsAccountLocked(ctx, testUserID)
	require.True(t, locked)

	// 重置不应解锁（lockout key 有 EXPIRE，自然过期；管理员强制解锁是单独动作）
	l.ResetFailures(ctx, ip, testUserID)
	locked, _ = l.IsAccountLocked(ctx, testUserID)
	assert.True(t, locked, "Reset 不清 lockout")
}

// === Window 滑动：旧失败应被清出 ===

func TestRecordFailure_WindowSlide(t *testing.T) {
	l, raw := setupLockout(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("203.0.113.60")

	// 手工注入"很早的失败"（直接 ZAdd，score 在窗口外）
	old := time.Now().Add(-2 * time.Hour).Unix()
	for i := 0; i < 5; i++ {
		raw.ZAdd(ctx, keyFailureAccountPrefix+testUserID, redis.Z{
			Score:  float64(old + int64(i)),
			Member: "old-" + string(rune('0'+i)),
		})
	}

	// 新一次失败应触发 ZRemRangeByScore 清掉旧的；窗内只有这一次 → 不该锁
	acct, _ := l.RecordFailure(ctx, ip, testUserID)
	assert.False(t, acct, "窗外的旧失败应被清出，新计数 = 1")
}
