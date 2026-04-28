// Package pg 包装 pgxpool 提供 RedMatrix 后端的多池 PG 连接管理。
//
// 设计原则（docs/LLD/22-rls-implementation.md §4.4 + 04-config-schema §2.1）：
//
//	┌────────────────────┬─────────────────────┬────────────────────────────────┐
//	│ 池                 │ 角色                │ RLS 行为                       │
//	├────────────────────┼─────────────────────┼────────────────────────────────┤
//	│ Pool.App           │ redmatrix_app       │ 受 RLS 强制约束，每查询前必须  │
//	│                    │                     │ 通过 SetTenant 注入 tenant_id  │
//	│ Pool.Maintenance   │ redmatrix_maintenance│ 旁路 RLS（pg_partman 后台 / 备份│
//	│                    │                     │ / 跨租户运维查询）             │
//	│ Pool.Admin         │ redmatrix_admin     │ 可选；仅 goose 迁移连接，启动后│
//	│                    │                     │ 立即关闭，不长期持有           │
//	└────────────────────┴─────────────────────┴────────────────────────────────┘
//
// 连接池参数默认与 04 §3.1 connection_pools.pg 对齐（max=25 / min=5 / lifetime=30m / idle=10m）。
package pg

import (
	"context"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sync/errgroup"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Config 描述多池配置。Open 自动忽略空 DSN 段（如不配 Admin 则 Pool.Admin 为 nil）。
type Config struct {
	AppDSN         string // redmatrix_app DSN（必填）
	MaintenanceDSN string // redmatrix_maintenance DSN（必填）
	AdminDSN       string // redmatrix_admin DSN（可选）

	// 池上限（每池独立）。0 = 用默认。
	AppMaxConns         int32
	AppMinConns         int32
	MaintenanceMaxConns int32
	MaintenanceMinConns int32
	AdminMaxConns       int32

	// 连接生命周期。0 = 用默认。
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// Pool 持有 1-3 个 pgxpool.Pool。Close 后所有底层池关闭。
type Pool struct {
	App         *pgxpool.Pool
	Maintenance *pgxpool.Pool
	Admin       *pgxpool.Pool // nil 当 Config.AdminDSN 为空
}

// 默认值（与 04-config-schema.md §3.1 connection_pools.pg 段一致）。
const (
	defaultAppMaxConns         = 25
	defaultAppMinConns         = 5
	defaultMaintenanceMaxConns = 10
	defaultMaintenanceMinConns = 1
	defaultAdminMaxConns       = 5
	defaultConnMaxLifetime     = 30 * time.Minute
	defaultConnMaxIdleTime     = 10 * time.Minute
)

// Open 解析每个非空 DSN，构造对应连接池。
//
// 返回 *Pool 时：
//   - App / Maintenance 必非 nil（DSN 必填，缺失返回 BOOTSTRAP_CONFIG_INVALID）
//   - Admin 仅当 Config.AdminDSN 非空时非 nil
//
// 注意：pgxpool.New 不会立即建连，仅解析 DSN。请在 Open 后单独调 Ping 探活。
func Open(ctx context.Context, cfg Config) (*Pool, error) {
	if cfg.AppDSN == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid, "AppDSN 必填").
			WithFields("var", "PG_DSN")
	}
	if cfg.MaintenanceDSN == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid, "MaintenanceDSN 必填").
			WithFields("var", "PG_DSN_MAINTENANCE")
	}
	cfg = withDefaults(cfg)

	app, err := openOne(ctx, cfg.AppDSN,
		cfg.AppMaxConns, cfg.AppMinConns,
		cfg.ConnMaxLifetime, cfg.ConnMaxIdleTime, "app")
	if err != nil {
		return nil, err
	}

	maint, err := openOne(ctx, cfg.MaintenanceDSN,
		cfg.MaintenanceMaxConns, cfg.MaintenanceMinConns,
		cfg.ConnMaxLifetime, cfg.ConnMaxIdleTime, "maintenance")
	if err != nil {
		app.Close()
		return nil, err
	}

	var admin *pgxpool.Pool
	if cfg.AdminDSN != "" {
		admin, err = openOne(ctx, cfg.AdminDSN,
			cfg.AdminMaxConns, 1,
			cfg.ConnMaxLifetime, cfg.ConnMaxIdleTime, "admin")
		if err != nil {
			app.Close()
			maint.Close()
			return nil, err
		}
	}

	return &Pool{App: app, Maintenance: maint, Admin: admin}, nil
}

// openOne 打开单个连接池。配置失败 → BOOTSTRAP_CONFIG_INVALID。
func openOne(ctx context.Context, dsn string, maxConns, minConns int32,
	lifetime, idle time.Duration, label string,
) (*pgxpool.Pool, error) {
	pcfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapConfigInvalid, err,
			"PG DSN 解析失败").WithFields("pool", label)
	}
	pcfg.MaxConns = maxConns
	pcfg.MinConns = minConns
	pcfg.MaxConnLifetime = lifetime
	pcfg.MaxConnIdleTime = idle

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
			"PG 连接池构造失败").WithFields("pool", label)
	}
	return pool, nil
}

// Ping 并发探活所有非 nil 池；任一失败返回 BOOTSTRAP_DB_UNREACHABLE。
//
// 用法（cmd/server boot 序列）：
//
//	pingCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
//	defer cancel()
//	if err := pool.Ping(pingCtx); err != nil { exit 1 }
func (p *Pool) Ping(ctx context.Context) error {
	if p == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "Pool 未初始化")
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return pingOne(gctx, p.App, "app") })
	g.Go(func() error { return pingOne(gctx, p.Maintenance, "maintenance") })
	if p.Admin != nil {
		g.Go(func() error { return pingOne(gctx, p.Admin, "admin") })
	}
	return g.Wait()
}

func pingOne(ctx context.Context, pool *pgxpool.Pool, label string) error {
	if pool == nil {
		return nil
	}
	if err := pool.Ping(ctx); err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
			"PG 池探活失败").WithFields("pool", label)
	}
	return nil
}

// Close 关闭所有底层池。Close 后 *Pool 不可复用。多次 Close 安全（pgxpool.Close 幂等）。
func (p *Pool) Close() {
	if p == nil {
		return
	}
	if p.App != nil {
		p.App.Close()
	}
	if p.Maintenance != nil {
		p.Maintenance.Close()
	}
	if p.Admin != nil {
		p.Admin.Close()
	}
}

// Stats 返回所有池的当前统计快照（用于 /metrics）。
type Stats struct {
	App         *pgxpool.Stat
	Maintenance *pgxpool.Stat
	Admin       *pgxpool.Stat // nil 当 Pool.Admin 为 nil
}

// Stats 采集当前所有池的统计。
func (p *Pool) Stats() Stats {
	if p == nil {
		return Stats{}
	}
	s := Stats{}
	if p.App != nil {
		s.App = p.App.Stat()
	}
	if p.Maintenance != nil {
		s.Maintenance = p.Maintenance.Stat()
	}
	if p.Admin != nil {
		s.Admin = p.Admin.Stat()
	}
	return s
}

// Sanitize 移除 DSN 中的密码，便于日志输出。失败返回 "<invalid dsn>"。
//
// 例：
//
//	postgres://user:secret@host/db → postgres://user:xxxxx@host/db
//
// （url.URL.Redacted 标准库实现）
func Sanitize(dsn string) string {
	if dsn == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return "<invalid dsn>"
	}
	return u.Redacted()
}

// withDefaults 把 cfg 中为 0 的池参数填上默认值。
//
// 关键：MaxConns 显式 > 0 时，对应 MinConns 不再回填默认（防止用户期望"小池"
// 但被默认 MinConns 反向放大）。这也让测试可以通过 MaxConns:1 + MinConns:0
// 的组合得到一个真正不主动建连的池。
func withDefaults(cfg Config) Config {
	if cfg.AppMaxConns == 0 {
		cfg.AppMaxConns = defaultAppMaxConns
		if cfg.AppMinConns == 0 {
			cfg.AppMinConns = defaultAppMinConns
		}
	}
	if cfg.MaintenanceMaxConns == 0 {
		cfg.MaintenanceMaxConns = defaultMaintenanceMaxConns
		if cfg.MaintenanceMinConns == 0 {
			cfg.MaintenanceMinConns = defaultMaintenanceMinConns
		}
	}
	if cfg.AdminMaxConns == 0 {
		cfg.AdminMaxConns = defaultAdminMaxConns
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = defaultConnMaxLifetime
	}
	if cfg.ConnMaxIdleTime == 0 {
		cfg.ConnMaxIdleTime = defaultConnMaxIdleTime
	}
	return cfg
}
