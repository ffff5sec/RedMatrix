//go:build integration

package policy

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rmredis "github.com/ffff5sec/RedMatrix/internal/storage/redis"
	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

func setupCaptcha(t *testing.T) (Captcha, *redis.Client) {
	t.Helper()
	h := redisharness.Start(t)

	c, err := rmredis.Open(context.Background(), rmredis.Config{URL: h.URL})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.Ping(context.Background()))

	cfg := DefaultCaptchaConfig()
	cfg.TTL = 2 * time.Second // 缩短便于过期测试
	cap, err := NewRedisCaptcha(c.Client, cfg)
	require.NoError(t, err)
	return cap, c.Client
}

// === Generate ===

func TestCaptcha_Generate_WritesToRedis(t *testing.T) {
	cap, raw := setupCaptcha(t)
	ctx := context.Background()

	ch, err := cap.Generate(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, ch.ID)
	require.NotEmpty(t, ch.Image)

	// PNG 头：89 50 4E 47
	require.True(t, len(ch.Image) > 8)
	assert.Equal(t, byte(0x89), ch.Image[0])
	assert.Equal(t, byte(0x50), ch.Image[1])

	// Redis 里应有 key
	got, err := raw.Get(ctx, keyCaptchaPrefix+ch.ID).Result()
	require.NoError(t, err)
	assert.Len(t, got, 6) // DefaultCaptchaConfig.Length=6
}

// === Verify happy path ===

func TestCaptcha_Verify_Correct(t *testing.T) {
	cap, raw := setupCaptcha(t)
	ctx := context.Background()

	ch, err := cap.Generate(ctx)
	require.NoError(t, err)

	// 直接从 Redis 读答案（用例需求；生产用户从图片识别）
	answer, err := raw.Get(ctx, keyCaptchaPrefix+ch.ID).Result()
	require.NoError(t, err)

	ok, err := cap.Verify(ctx, ch.ID, answer)
	require.NoError(t, err)
	assert.True(t, ok)

	// 单次性：再次验证应返 false（key 已 DEL）
	ok, err = cap.Verify(ctx, ch.ID, answer)
	require.NoError(t, err)
	assert.False(t, ok, "Verify 命中后应立即 DEL，重放失败")
}

// === Verify wrong answer ===

func TestCaptcha_Verify_WrongAnswer(t *testing.T) {
	cap, raw := setupCaptcha(t)
	ctx := context.Background()

	ch, err := cap.Generate(ctx)
	require.NoError(t, err)

	// 故意填错
	ok, err := cap.Verify(ctx, ch.ID, "000000")
	require.NoError(t, err)
	assert.False(t, ok)

	// 防爆破：错答案命中 key 也要 DEL；再用对的答案也应失败
	answer, err := raw.Get(ctx, keyCaptchaPrefix+ch.ID).Result()
	if err == nil {
		// key 还在 → 测试设计错误
		t.Fatalf("Verify 错答案后 Key 应已 DEL，但 GET 仍返: %s", answer)
	}
}

// === Verify expired ===

func TestCaptcha_Verify_Expired(t *testing.T) {
	cap, _ := setupCaptcha(t)
	ctx := context.Background()

	ch, err := cap.Generate(ctx)
	require.NoError(t, err)

	// TTL=2s，等 3s 让其过期
	time.Sleep(3 * time.Second)

	ok, err := cap.Verify(ctx, ch.ID, "anything")
	require.NoError(t, err)
	assert.False(t, ok, "过期的验证码应返 false")
}

// === Verify empty inputs ===

func TestCaptcha_Verify_EmptyInputs(t *testing.T) {
	cap, _ := setupCaptcha(t)
	ctx := context.Background()

	ok, err := cap.Verify(ctx, "", "abc")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = cap.Verify(ctx, "id", "")
	require.NoError(t, err)
	assert.False(t, ok)
}

// === Verify trims whitespace ===

func TestCaptcha_Verify_TrimsAnswer(t *testing.T) {
	cap, raw := setupCaptcha(t)
	ctx := context.Background()

	ch, err := cap.Generate(ctx)
	require.NoError(t, err)
	answer, err := raw.Get(ctx, keyCaptchaPrefix+ch.ID).Result()
	require.NoError(t, err)

	ok, err := cap.Verify(ctx, ch.ID, "  "+answer+"  ")
	require.NoError(t, err)
	assert.True(t, ok, "答案前后空白应被 trim")
}
