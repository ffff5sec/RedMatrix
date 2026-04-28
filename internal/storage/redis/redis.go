// Package redis 包装 go-redis/v9 提供 RedMatrix 后端单 Redis 实例的连接管理。
//
// 设计原则（docs/LLD/01-database-schema.md §3 + 04-config-schema.md §2.1）：
//   - 单进程单 client（go-redis 内部已是连接池）
//   - DB 0：缓存与限流（可被 LRU 淘汰）
//   - DB 1：队列与分布式锁（noeviction 策略）
//   - 启动期 Ping 探活；失败映射 BOOTSTRAP_DB_UNREACHABLE
//
// DB 切换由调用方在每次操作前显式 SELECT；本包不在 client 上锁定 DB。
package redis

import (
	"context"
	"net/url"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Config Redis 连接配置（与 04-config-schema.md §3.1 connection_pools.redis 段对齐）。
type Config struct {
	URL string // redis://[:pass@]host:port/db 或 rediss://（TLS）

	// 池上限（0 = 用默认）。
	// PoolSize 默认 10 × CPU；MinIdleConns 默认 5。但若调用方显式设置
	// PoolSize > 0，MinIdleConns 不再回填默认（避免不可达 URL 时后台重连拖死测试）。
	PoolSize     int
	MinIdleConns int

	MaxRetries int

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// 默认值（与 04-config-schema.md §3.1 connection_pools.redis 段对齐）。
const (
	defaultMaxRetries   = 3
	defaultDialTimeout  = 5 * time.Second
	defaultReadTimeout  = 3 * time.Second
	defaultWriteTimeout = 3 * time.Second
	defaultMinIdleConns = 5
)

// Client 包装 *redis.Client。Embed 模式让调用方直接用 go-redis API（Get/Set/HSet 等）。
type Client struct {
	*redis.Client
}

// Open 解析 URL 构造 Client。不主动建连（go-redis 是 lazy）。
//
// URL 必填；缺失返回 BOOTSTRAP_CONFIG_INVALID。
// URL 解析失败返回 BOOTSTRAP_CONFIG_INVALID。
func Open(_ context.Context, cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"Redis URL 必填").WithFields("var", "REDIS_URL")
	}

	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapConfigInvalid, err,
			"Redis URL 解析失败").WithFields("var", "REDIS_URL")
	}

	cfg = withDefaults(cfg)
	opt.PoolSize = cfg.PoolSize
	opt.MinIdleConns = cfg.MinIdleConns
	opt.MaxRetries = cfg.MaxRetries
	opt.DialTimeout = cfg.DialTimeout
	opt.ReadTimeout = cfg.ReadTimeout
	opt.WriteTimeout = cfg.WriteTimeout

	return &Client{Client: redis.NewClient(opt)}, nil
}

// Ping 探活。失败 → BOOTSTRAP_DB_UNREACHABLE。
//
// 用法（cmd/server boot 序列）：
//
//	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
//	defer cancel()
//	if err := client.Ping(pingCtx); err != nil { exit 1 }
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.Client == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "Redis client 未初始化")
	}
	if err := c.Client.Ping(ctx).Err(); err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err, "Redis ping 失败")
	}
	return nil
}

// Close 关闭底层连接池。多次 Close 安全。
func (c *Client) Close() error {
	if c == nil || c.Client == nil {
		return nil
	}
	return c.Client.Close()
}

// Stats 返回当前连接池统计。
type Stats = redis.PoolStats

// Stats 采集。
func (c *Client) Stats() *Stats {
	if c == nil || c.Client == nil {
		return nil
	}
	s := c.Client.PoolStats()
	return s
}

// Sanitize 移除 URL 中的密码（日志用）。空 / 非法返回 "" / "<invalid redis url>"。
func Sanitize(redisURL string) string {
	if redisURL == "" {
		return ""
	}
	u, err := url.Parse(redisURL)
	if err != nil {
		return "<invalid redis url>"
	}
	return u.Redacted()
}

// withDefaults 把 cfg 中为 0 的池参数填上默认值。
//
// 关键：PoolSize 显式 > 0 时不再回填 MinIdleConns 默认，避免不可达 URL 测试场景
// 因后台 idle 维护重连而拖慢（与 internal/storage/pg withDefaults 同模式）。
func withDefaults(cfg Config) Config {
	if cfg.PoolSize == 0 {
		// PoolSize 默认走 go-redis 自身（10 × runtime.GOMAXPROCS）；不在此覆盖。
		// 但需要回填 MinIdleConns，因为零值是 0（go-redis 不会自动维护）。
		if cfg.MinIdleConns == 0 {
			cfg.MinIdleConns = defaultMinIdleConns
		}
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = defaultReadTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	return cfg
}
