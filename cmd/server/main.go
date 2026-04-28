// Command redmatrix-server 是 RedMatrix 平台中心的入口。
//
// boot 流水线（截至当前 PR）：
//  1. 加载 env 配置（internal/config）
//  2. 静态 fail-fast 校验（密钥强度 / 三密钥互异 / PG sslmode / role 名 / log 取值）
//  3. 初始化日志门面（internal/platform/log）并 SetDefault
//  4. 输出版本 + 配置摘要（绝不打印密钥 / 凭据）
//  5. 打开 PG 连接池（internal/storage/pg）— 三池：app / maintenance / 可选 admin
//  6. Ping PG（30s ctx 超时）→ BOOTSTRAP_DB_UNREACHABLE 失败立即退出
//  7. 可选：RM_AUTO_MIGRATE=true 且 PG_DSN_ADMIN 非空 → 跑 goose Up
//  8. （TODO）ES / Redis / MinIO 探活
//  9. （TODO）注册 handler / 监听 / 等 SIGTERM
//
// 退出码（与 docs/LLD/40-deployment-detail.md §2.5 / §9.6 对齐）：
//
//	0 — 成功
//	1 — 运行时失败（迁移失败 / 探活失败 / 监听失败等）
//	2 — bootstrap fatal（必填缺失 / 密钥不合法 / 配置取值非法等）
package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql 驱动注册（goose 用）

	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	"github.com/ffff5sec/RedMatrix/internal/storage/redis"
	"github.com/ffff5sec/RedMatrix/internal/version"
)

const (
	// defaultPGPingTimeout 启动期 PG 探活的超时上限（生产）。
	// 与 40 §2.5 启动 fail-fast 行为对齐。
	defaultPGPingTimeout = 30 * time.Second

	// defaultRedisPingTimeout 启动期 Redis 探活的超时上限。
	defaultRedisPingTimeout = 10 * time.Second

	// defaultMigrateTimeout 一次完整 goose Up 的超时上限。
	defaultMigrateTimeout = 5 * time.Minute
)

// runOptions 让测试可控地缩短启动超时（不可达存储时避免每个测试 30s × N 卡死）。
// 生产路径（main → run）一律走默认值。
type runOptions struct {
	pgPingTimeout    time.Duration
	redisPingTimeout time.Duration
	migrateTimeout   time.Duration
	pgPoolOverride   func(cfg pg.Config) pg.Config       // 测试用：例如把 MinConns 设 0
	redisOverride    func(cfg redis.Config) redis.Config // 测试用：把 MinIdleConns 设 0
}

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

// run 是生产入口，使用默认 options。
func run(stdout, stderr io.Writer) int {
	return runWith(stdout, stderr, runOptions{})
}

// runWith 是可测试入口，允许注入超时 / 池配置覆盖。
func runWith(stdout, stderr io.Writer, opts runOptions) int {
	cfg, err := config.Load()
	if err != nil {
		return fail(stderr, err)
	}
	if err := cfg.Validate(); err != nil {
		return fail(stderr, err)
	}

	logger, err := log.New(log.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: stdout,
	})
	if err != nil {
		return fail(stderr, err)
	}
	log.SetDefault(logger)

	logger.Info("redmatrix-server starting",
		"version", version.Version,
		"commit", version.Commit,
		"build_date", version.BuildDate,
		"env", cfg.Env,
	)
	logBootSummary(logger, cfg)

	ctx := context.Background()
	pgTimeout := opts.pgPingTimeout
	if pgTimeout == 0 {
		pgTimeout = defaultPGPingTimeout
	}
	redisTimeout := opts.redisPingTimeout
	if redisTimeout == 0 {
		redisTimeout = defaultRedisPingTimeout
	}
	migTimeout := opts.migrateTimeout
	if migTimeout == 0 {
		migTimeout = defaultMigrateTimeout
	}

	// === 5/6. 打开 PG 连接池并探活 ===
	poolCfg := pg.Config{
		AppDSN:         cfg.DB.PGDSN,
		MaintenanceDSN: cfg.DB.PGMaintenanceDSN,
		AdminDSN:       cfg.DB.PGAdminDSN,
	}
	if opts.pgPoolOverride != nil {
		poolCfg = opts.pgPoolOverride(poolCfg)
	}
	pool, err := pg.Open(ctx, poolCfg)
	if err != nil {
		logger.LogError(ctx, "pg open failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	defer pool.Close()

	pingCtx, cancelPing := context.WithTimeout(ctx, pgTimeout)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		logger.LogError(pingCtx, "pg ping failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	logger.Info("pg pools ready",
		"app.dsn", pg.Sanitize(cfg.DB.PGDSN),
		"maintenance.dsn", pg.Sanitize(cfg.DB.PGMaintenanceDSN),
		"admin.enabled", pool.Admin != nil,
	)

	// === 6b. Redis ===
	redisCfg := redis.Config{URL: cfg.DB.RedisURL}
	if opts.redisOverride != nil {
		redisCfg = opts.redisOverride(redisCfg)
	}
	rds, err := redis.Open(ctx, redisCfg)
	if err != nil {
		logger.LogError(ctx, "redis open failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	defer func() { _ = rds.Close() }()

	rdsCtx, cancelRds := context.WithTimeout(ctx, redisTimeout)
	defer cancelRds()
	if err := rds.Ping(rdsCtx); err != nil {
		logger.LogError(rdsCtx, "redis ping failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	logger.Info("redis ready",
		"url", redis.Sanitize(cfg.DB.RedisURL),
	)

	// === 7. 可选：自动跑迁移 ===
	if cfg.Dev.AutoMigrate {
		if err := autoMigrate(ctx, logger, cfg, migTimeout); err != nil {
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
	}

	// TODO(scaffold): ES / Redis / MinIO 探活 → 注册 handler → 监听 → 等 SIGTERM。
	logger.Info("scaffold boot complete; exiting until RPC wiring lands")
	return 0
}

// autoMigrate 应用所有未执行迁移。需 PG_DSN_ADMIN（仅 admin role 可 DDL）。
//
// 与 docs/LLD/40-deployment-detail.md D40-07 对齐：
// 生产档不应该让 redmatrix-server 自己跑迁移（CI 做），AutoMigrate 仅开发档默认 true。
func autoMigrate(ctx context.Context, logger *log.Logger, cfg *config.Config, timeout time.Duration) error {
	if cfg.DB.PGAdminDSN == "" {
		logger.Warn("RM_AUTO_MIGRATE=true 但 PG_DSN_ADMIN 未配置；跳过迁移",
			"hint", "生产档由 CI 用 PG_DSN_ADMIN 跑 goose；server 不需直接持有 admin 凭据")
		return nil
	}

	mctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := sql.Open("pgx", cfg.DB.PGAdminDSN)
	if err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
			"打开 admin sql.DB 失败").WithFields("var", "PG_DSN_ADMIN")
	}
	defer db.Close()

	if err := migrate.Up(mctx, db); err != nil {
		logger.LogError(mctx, "auto-migrate 失败", err)
		return err
	}
	logger.Info("auto-migrate applied")
	return nil
}

// fail 把 err 写 stderr + 计算退出码。
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
	return failExitCode(err)
}

// failExitCode 把 BOOTSTRAP_* 错误码映射为 exit 2，其它为 1。
func failExitCode(err error) int {
	code, ok := errx.GetCode(err)
	if !ok {
		return 1
	}
	if strings.HasPrefix(string(code), "BOOTSTRAP_") {
		return 2
	}
	return 1
}

// logBootSummary 输出非敏感配置摘要。
//
// 严格不打印的字段：PG/Redis DSN（含密码）、MinIO 凭据、JWT_SECRET、ENCRYPTION_KEY /
// AUDIT_HMAC_KEY / BACKUP_KEY、Bootstrap.Password。
// 仅打印长度 / 字节数辅助验证非空；DSN 走 pg.Sanitize 脱敏后输出。
func logBootSummary(l *log.Logger, cfg *config.Config) {
	l.Info("config loaded",
		"public.domain", cfg.Public.Domain,
		"public.grpc_addr", cfg.Public.GRPCAddr,
		"public.ingest_addr", cfg.Public.IngestAddr,
		"public.minio_addr", cfg.Public.MinIOAddr,
		"public.grafana_url", cfg.Public.GrafanaURL,
		"db.es_url", cfg.DB.ESURL,
		"db.minio_endpoint", cfg.DB.MinIOEndpoint,
		"db.minio_public_endpoint", cfg.DB.MinIOPublicEndpoint,
		"db.pg_admin_configured", cfg.DB.PGAdminDSN != "",
		"log.level", cfg.Log.Level,
		"log.format", cfg.Log.Format,
		"dev.auto_migrate", cfg.Dev.AutoMigrate,
		"dev.dev_mode", cfg.Dev.DevMode,
		"dev.le_staging", cfg.Dev.LEStaging,
		"bootstrap.username", cfg.Bootstrap.Username,
		"bootstrap.email", cfg.Bootstrap.Email,
		"crypto.jwt_secret_len", len(cfg.Crypto.JWTSecret),
		"crypto.encryption_key_bytes", len(cfg.Crypto.EncryptionKey),
		"crypto.audit_hmac_key_bytes", len(cfg.Crypto.AuditHMACKey),
		"crypto.backup_key_bytes", len(cfg.Crypto.BackupKey),
	)
}
