// Package policy 的验证码（captcha）部分。
//
// LLD 10 §4.6：图片验证码 4-6 字符，Redis 存答案，5m TTL（来自 01-database-schema §3.2
// `global:captcha:{captcha_id}` String/5m）。单次性：Verify 命中后立即删除 Key，
// 避免重放。
//
// 触发策略：
//   - cfg.Enabled=false → 永不需要
//   - cfg.AlwaysShow=true（MVP 默认）→ 每次登录都要
//   - cfg.AlwaysShow=false → 失败次数 ≥ 阈值才要（PR2-C₂ 暂未实现，IsRequired 返 false）
//
// 失败 fail-open：Redis 故障时 Generate 透明返错给 caller；Verify 故障返 false（拒登录）；
// IsRequired 故障返 false（不阻塞登录）。
package policy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/dchest/captcha"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// CaptchaConfig 来自 04-config §security.captcha + 默认尺寸常量。
type CaptchaConfig struct {
	Enabled    bool
	AlwaysShow bool
	Length     int           // 字符数（4-6）
	Width      int           // 图片宽
	Height     int           // 图片高
	TTL        time.Duration // Redis Key 存活时长
}

// DefaultCaptchaConfig 来自 LLD 10 §4.6 + LLD 04 默认。
func DefaultCaptchaConfig() CaptchaConfig {
	return CaptchaConfig{
		Enabled:    true,
		AlwaysShow: true,
		Length:     6,
		Width:      240,
		Height:     80,
		TTL:        5 * time.Minute,
	}
}

// Validate 检查必填项；Length ∈ [4,6]，TTL > 0，Width/Height > 0。
func (c CaptchaConfig) Validate() error {
	if !c.Enabled {
		// 关闭态不校验其他字段（避免 dev 环境写一堆 0 也算合法）
		return nil
	}
	if c.Length < 4 || c.Length > 6 {
		return errx.New(errx.ErrInvalidInput, "captcha: Length 必须在 [4,6]")
	}
	if c.Width <= 0 || c.Height <= 0 {
		return errx.New(errx.ErrInvalidInput, "captcha: Width/Height 必须 > 0")
	}
	if c.TTL <= 0 {
		return errx.New(errx.ErrInvalidInput, "captcha: TTL 必须 > 0")
	}
	return nil
}

// CaptchaChallenge 是 Generate 返回结构：ID 给前端回传，Image 是 PNG 字节。
type CaptchaChallenge struct {
	ID    string
	Image []byte
}

// Captcha 是策略层接口，AuthService 依赖此接口。
type Captcha interface {
	// Generate 生成新验证码（写 Redis），返回 (id, png)。
	// 失败：Redis 故障 / 配置非法 → 返 errx 错。
	Generate(ctx context.Context) (CaptchaChallenge, error)

	// Verify 校验答案；成功返 true。命中 key 后无论对错都立即 DEL（防爆破）。
	// 失败 / Key 不存在 / 已过期：返 false（不区分原因，防侧信道）。
	Verify(ctx context.Context, id, answer string) (bool, error)

	// IsRequired 判断本次 Login 是否需要验证码。
	IsRequired(ctx context.Context, ip netip.Addr, userID string) bool
}

// === Redis 实现 ===

// keyCaptchaPrefix 与 LLD 01 §3.2 对齐。
const keyCaptchaPrefix = "global:captcha:"

// redisCaptcha 用 go-redis 实现 Captcha；图像渲染走 dchest/captcha NewImage。
type redisCaptcha struct {
	client redis.Cmdable
	cfg    CaptchaConfig

	// 注入点（测试用）
	randDigits func(length int) []byte
	newID      func() string
	render     func(id string, digits []byte, w, h int) ([]byte, error)
}

// NewRedisCaptcha 构造 Redis-backed Captcha。
func NewRedisCaptcha(client redis.Cmdable, cfg CaptchaConfig) (Captcha, error) {
	if client == nil {
		return nil, errx.New(errx.ErrInvalidInput, "policy.NewRedisCaptcha: client 不能为 nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &redisCaptcha{
		client:     client,
		cfg:        cfg,
		randDigits: captcha.RandomDigits,
		newID:      uuid.NewString,
		render:     renderImage,
	}, nil
}

// renderImage 调 dchest/captcha 渲染 PNG。
func renderImage(id string, digits []byte, w, h int) ([]byte, error) {
	img := captcha.NewImage(id, digits, w, h)
	var buf bytes.Buffer
	if _, err := img.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Generate 生成验证码 + 存 Redis。
func (c *redisCaptcha) Generate(ctx context.Context) (CaptchaChallenge, error) {
	if !c.cfg.Enabled {
		return CaptchaChallenge{}, errx.New(errx.ErrInternal, "captcha: 已禁用")
	}
	digits := c.randDigits(c.cfg.Length)
	id := c.newID()

	png, err := c.render(id, digits, c.cfg.Width, c.cfg.Height)
	if err != nil {
		return CaptchaChallenge{}, errx.Wrap(errx.ErrInternal, err, "captcha: 图像渲染失败")
	}

	// 存 Redis："123456" 形式的字符串便于跨语言对比
	answer := digitsToString(digits)
	if err := c.client.Set(ctx, keyCaptchaPrefix+id, answer, c.cfg.TTL).Err(); err != nil {
		return CaptchaChallenge{}, errx.Wrap(errx.ErrInternal, err, "captcha: Redis 写入失败")
	}
	return CaptchaChallenge{ID: id, Image: png}, nil
}

// Verify 校验答案（单次性：命中后 DEL）。
func (c *redisCaptcha) Verify(ctx context.Context, id, answer string) (bool, error) {
	if id == "" || answer == "" {
		return false, nil
	}
	key := keyCaptchaPrefix + id
	stored, err := c.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil // 已过期 / 已用 / 不存在
	}
	if err != nil {
		// Redis 故障：Verify 不 fail-open（防绕过）；上层据此返 AUTH_CAPTCHA_INVALID
		return false, errx.Wrap(errx.ErrInternal, err, "captcha: Redis 读取失败")
	}

	// 命中即 DEL（无论对错）：防爆破。DEL 失败仅记日志，不阻塞判定。
	_ = c.client.Del(ctx, key).Err()

	// 常数时间比较 + 大小写无关 + 去空白
	got := strings.TrimSpace(answer)
	if subtle.ConstantTimeCompare([]byte(got), []byte(stored)) != 1 {
		return false, nil
	}
	return true, nil
}

// IsRequired 判断 Login 是否需要验证码。
//
// PR2-C₂ 仅实现 always_show：
//   - !Enabled → false
//   - AlwaysShow → true
//   - 其他 → false（TODO：依失败计数动态触发，由后续 PR 补）
//
// _ip / _userID 占位，留给 always_show=false 路径用。
func (c *redisCaptcha) IsRequired(_ context.Context, _ netip.Addr, _ string) bool {
	if !c.cfg.Enabled {
		return false
	}
	return c.cfg.AlwaysShow
}

// digitsToString [1,2,3] -> "123"。
func digitsToString(digits []byte) string {
	var sb strings.Builder
	sb.Grow(len(digits))
	for _, d := range digits {
		sb.WriteByte('0' + d)
	}
	return sb.String()
}
