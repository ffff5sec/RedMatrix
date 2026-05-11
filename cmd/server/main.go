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
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql 驱动注册（goose 用）

	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/bootstrapcheck"
	"github.com/ffff5sec/RedMatrix/internal/platform/eventbus"
	"github.com/ffff5sec/RedMatrix/internal/platform/health"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/platform/metrics"
	"github.com/ffff5sec/RedMatrix/internal/scan/artifact"
	"github.com/ffff5sec/RedMatrix/internal/scan/metricsscan"
	"github.com/ffff5sec/RedMatrix/internal/scan/sweeper"
	"github.com/ffff5sec/RedMatrix/internal/storage/es"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	rmminio "github.com/ffff5sec/RedMatrix/internal/storage/minio"
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

	// defaultESPingTimeout 启动期 ES cluster health 探活的超时上限。
	defaultESPingTimeout = 15 * time.Second

	// defaultMinioPingTimeout 启动期 MinIO ListBuckets + 9 bucket 校验的超时上限。
	defaultMinioPingTimeout = 15 * time.Second

	// defaultMigrateTimeout 一次完整 goose Up 的超时上限。
	defaultMigrateTimeout = 5 * time.Minute

	// defaultHTTPBindAddr 是 main 的默认监听地址（与 04-config-schema §3.1
	// server.http.bind 对齐；后续接 RPC handler 会用同一端口）。
	defaultHTTPBindAddr = ":8080"

	// defaultHTTPReadHeaderTimeout 防 Slowloris：限制 header 读取上限。
	defaultHTTPReadHeaderTimeout = 5 * time.Second

	// defaultShutdownTimeout HTTP server graceful shutdown 上限。
	defaultShutdownTimeout = 10 * time.Second

	// defaultProbeTimeout health Aggregator 单 probe 超时（小于 PG ping 默认）。
	defaultProbeTimeout = 3 * time.Second
)

// runOptions 让测试可控地缩短启动超时（不可达存储时避免每个测试 30s × N 卡死）。
// 生产路径（main → run）一律走默认值。
type runOptions struct {
	pgPingTimeout    time.Duration
	redisPingTimeout time.Duration
	esPingTimeout    time.Duration
	minioPingTimeout time.Duration
	migrateTimeout   time.Duration
	pgPoolOverride   func(cfg pg.Config) pg.Config           // 测试用：例如把 MinConns 设 0
	redisOverride    func(cfg redis.Config) redis.Config     // 测试用：把 MinIdleConns 设 0
	esOverride       func(cfg es.Config) es.Config           // 测试用：超时 / dial
	minioOverride    func(cfg rmminio.Config) rmminio.Config // 测试用：endpoint / TLS
	// minioSkipVerify=true 时仅 Ping，不调 VerifyBuckets（用于 dev / 测试场景下
	// 容器还未跑 minio-bootstrap，让 boot 仍能通过）。
	minioSkipVerify bool

	// httpBindAddr 非空时启动 HTTP server 提供 /health + /ready；
	// 空时跳过（unit / boot integration 测试默认行为）。
	// 生产路径 main() 设 ":8080"。
	httpBindAddr string

	// ctx 控制 HTTP server 的生命周期。nil 时退化为 context.Background()。
	// main() 用 signal.NotifyContext 监听 SIGINT/SIGTERM 让进程优雅退出。
	ctx context.Context

	// onListening 在 HTTP server 实际监听后调用一次，回传 listener.Addr()。
	// 测试用：让外部知道 ":0" 被 OS 实际选中的端口。
	onListening func(addr string)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	rc := runWith(os.Stdout, os.Stderr, runOptions{
		ctx:          ctx,
		httpBindAddr: defaultHTTPBindAddr,
	})
	// 显式调 stop() 后再 os.Exit，避免 lint exitAfterDefer 警告
	// （os.Exit 跳过 defer，会让 signal.Notify 通道泄漏）。
	stop()
	os.Exit(rc)
}

// runWith 是可测试入口，允许注入超时 / 池配置覆盖。
func runWith(stdout, stderr io.Writer, opts runOptions) int {
	parentCtx := opts.ctx
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	_ = parentCtx // silence unused-warning until used below

	cfg, err := config.Load()
	if err != nil {
		return fail(stderr, err)
	}
	if err := cfg.Validate(); err != nil {
		return fail(stderr, err)
	}

	// danger guard 自检（占位符 / AWS key / PEM / 弱默认）。
	// 在 storage 打开前；命中即 BOOTSTRAP_GUARD_VIOLATION → exit 2。
	if err := bootstrapcheck.CheckConfig(cfg); err != nil {
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

	ctx := parentCtx
	pgTimeout := opts.pgPingTimeout
	if pgTimeout == 0 {
		pgTimeout = defaultPGPingTimeout
	}
	redisTimeout := opts.redisPingTimeout
	if redisTimeout == 0 {
		redisTimeout = defaultRedisPingTimeout
	}
	esTimeout := opts.esPingTimeout
	if esTimeout == 0 {
		esTimeout = defaultESPingTimeout
	}
	minioTimeout := opts.minioPingTimeout
	if minioTimeout == 0 {
		minioTimeout = defaultMinioPingTimeout
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

	// === 6c. ES cluster health ===
	esCfg := es.Config{URL: cfg.DB.ESURL}
	if opts.esOverride != nil {
		esCfg = opts.esOverride(esCfg)
	}
	esClient, err := es.Open(ctx, esCfg)
	if err != nil {
		logger.LogError(ctx, "es open failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	defer func() { _ = esClient.Close() }()

	esCtx, cancelES := context.WithTimeout(ctx, esTimeout)
	defer cancelES()
	if err := esClient.Ping(esCtx); err != nil {
		logger.LogError(esCtx, "es ping failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	if status, name, herr := esClient.Health(esCtx); herr == nil {
		logger.Info("es ready",
			"url", es.Sanitize(cfg.DB.ESURL),
			"cluster", name,
			"status", status,
		)
	} else {
		logger.Info("es ready", "url", es.Sanitize(cfg.DB.ESURL))
	}

	// === 6d. MinIO（Ping + 9 bucket 校验）===
	mioCfg := rmminio.Config{
		Endpoint:  cfg.DB.MinIOEndpoint,
		AccessKey: cfg.DB.MinIOAccessKey,
		SecretKey: cfg.DB.MinIOSecretKey,
		// 内网 endpoint 默认无 TLS；公网 endpoint 由调用方自管。
		UseSSL: false,
	}
	if opts.minioOverride != nil {
		mioCfg = opts.minioOverride(mioCfg)
	}
	mio, err := rmminio.Open(ctx, mioCfg)
	if err != nil {
		logger.LogError(ctx, "minio open failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	defer func() { _ = mio.Close() }()

	mioCtx, cancelMio := context.WithTimeout(ctx, minioTimeout)
	defer cancelMio()
	if err := mio.Ping(mioCtx); err != nil {
		logger.LogError(mioCtx, "minio ping failed", err)
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	if !opts.minioSkipVerify {
		if err := mio.VerifyBuckets(mioCtx, rmminio.RequiredBuckets); err != nil {
			logger.LogError(mioCtx, "minio bucket verify failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
	}
	logger.Info("minio ready",
		"endpoint", rmminio.Sanitize(cfg.DB.MinIOEndpoint, cfg.DB.MinIOAccessKey),
		"buckets_verified", !opts.minioSkipVerify,
	)

	// === 7. 可选：自动跑迁移 ===
	if cfg.Dev.AutoMigrate {
		if err := autoMigrate(ctx, logger, cfg, migTimeout); err != nil {
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
	}

	// === 8. HTTP server（/health + /ready；可选）===
	if opts.httpBindAddr != "" {
		aggregator := health.New(defaultProbeTimeout)
		aggregator.Register("pg", pool.Ping)
		aggregator.Register("redis", rds.Ping)
		aggregator.Register("es", esClient.Ping)
		aggregator.Register("minio", mio.Ping)

		metricsReg := metrics.New(version.Version, version.Commit, version.BuildDate)
		// PR-S17-OBSV: scan 业务指标（5 个核心 counter）
		scanMetrics := metricsscan.New(metricsReg)

		mux := http.NewServeMux()
		mux.Handle("/health", health.LivenessHandler())
		mux.Handle("/ready", aggregator.ReadinessHandler())
		mux.Handle("/metrics", metricsReg.Handler())

		// === 8a. IdentityService（ConnectRPC）===
		idMount, authSvc, err := buildIdentityMount(pool, rds, cfg.Crypto.JWTSecret)
		if err != nil {
			logger.LogError(ctx, "identity stack init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		mux.Handle(idMount.path, idMount.handler)
		logger.Info("identity service mounted", "path", idMount.path)

		// === 8a₁. TenancyService（ConnectRPC）===
		// 启动期 ensure CA：缺则生成；用于 RegistrationToken Redeem 签节点 cert。
		ca, err := ensureCA(logger)
		if err != nil {
			logger.LogError(ctx, "tenancy CA init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		tnMount, tenancySvc, err := buildTenancyMount(pool, authSvc, ca)
		if err != nil {
			logger.LogError(ctx, "tenancy stack init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		mux.Handle(tnMount.path, tnMount.handler)
		logger.Info("tenancy service mounted", "path", tnMount.path)

		// === 8a₂. AssetService（PR-S8 资产视图）===
		// 先于 ScanService 装：scan service 要把 AssetDeriver 注入做 ReportResults 派生。
		asMount, assetDeriver, err := buildAssetMount(pool, authSvc, logger)
		if err != nil {
			logger.LogError(ctx, "asset stack init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		mux.Handle(asMount.path, asMount.handler)
		logger.Info("asset service mounted", "path", asMount.path)

		// === 8a₂'. ArtifactStore（PR-S16 MinIO 预签名）===
		// MinIO 不可达不致命：artifactStore=nil → 相关 RPC 返 Unimplemented。
		artifactStore, err := artifact.New(mio, artifact.DefaultBucket)
		if err != nil {
			logger.LogError(ctx, "artifact store init failed (continuing)", err)
			artifactStore = nil
		} else {
			logger.Info("artifact store ready", "bucket", artifact.DefaultBucket)
		}

		// === 8a₃. ScanService（PR-S1 扫描调度入口）===
		// 先于 node_agent server 装：node_agent 的 PullTasks/ReportTaskProgress
		// 需要注入 scan.Service。同时返回 scheduler 让 main 控生命周期（PR-S12）。
		scMount, scanSvc, scanSched, err := buildScanMount(ctx, pool, esClient, authSvc, assetDeriver, artifactStore, scanMetrics, logger)
		if err != nil {
			logger.LogError(ctx, "scan stack init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		mux.Handle(scMount.path, scMount.handler)

		// PR-S12 加载已有 cron task → 启动调度器；ctx 取消时 Stop（等 job 完成）。
		if err := scanSched.LoadAll(ctx); err != nil {
			logger.LogError(ctx, "scan: scheduler LoadAll failed (continuing)", err)
		}
		scanSched.Start()
		defer scanSched.Stop()
		logger.Info("scan scheduler started", "cron_tasks", scanSched.Count())

		// === 8a₃'. Sweeper（PR-S14）—— 回收卡 running 超时的派发 ===
		// PR-S17-RACE：用 sweeperDone 让 shutdown 显式等 goroutine 退出，
		// 避免 pool.Close 后 sweeper 仍在中段 SQL。
		sw := sweeper.New(scanSvc, sweeper.DefaultInterval, sweeper.DefaultTimeout, logger)
		sweeperDone := make(chan struct{})
		go func() {
			defer close(sweeperDone)
			if err := sw.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				logger.LogError(ctx, "scan: sweeper exited with error", err)
			}
		}()
		logger.Info("scan sweeper started",
			"interval", sweeper.DefaultInterval.String(),
			"timeout", sweeper.DefaultTimeout.String())

		// === 8a₁'. NodeAgentService（mTLS-only；Agent 心跳 + 拉任务）===
		nodeAgentSrv, err := startNodeAgentServer(ctx, logger, pool, tenancySvc, scanSvc, artifactStore, ca, cfg.Public.GRPCAddr)
		if err != nil {
			logger.LogError(ctx, "node_agent server init failed", err)
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}
		logger.Info("scan service mounted", "path", scMount.path)

		// === 8a₂. Bootstrap tenancy（默认 account，幂等）===
		// 必须在 identity bootstrap 之前；后续创建非 SA 用户的 tenant_id 来自此处。
		if err := runTenancyBootstrap(ctx, logger, pool); err != nil {
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}

		// === 8a₃. Bootstrap admin（首启幂等）===
		// 用 maintenance 池：SuperAdmin tenant_id=NULL，绕开 RLS（待 tenancy 模块落地）
		if err := runBootstrap(ctx, logger, stdout, pool, cfg); err != nil {
			fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
			return failExitCode(err)
		}

		// === 8b. Async eventbus Relay ===
		// Relay 跑在独立 goroutine，与 HTTP server 共用 ctx；ctx 取消时同步退出。
		// Bus + Registry 在 boot 时为空 — 业务模块（待落）会调 RegisterType[T] +
		// Subscribe[T] 自管。空 Registry 时 Relay 遇到事件会标 failed（unknown topic），
		// 但 scaffold 阶段无业务 PublishTx 调用，pending 队列恒空。
		eventBus := eventbus.New(logger)
		eventRegistry := eventbus.NewRegistry()
		outbox := eventbus.NewOutbox(pool.Maintenance)
		relay := eventbus.NewRelay(outbox, eventBus, eventRegistry, eventbus.RelayConfig{}, logger)

		var relayWG sync.WaitGroup
		relayWG.Add(1)
		go func() {
			defer relayWG.Done()
			if err := relay.Run(ctx); err != nil {
				logger.LogError(ctx, "relay exited with error", err)
			}
		}()

		// === 8c. HTTP server ===
		listener, err := net.Listen("tcp", opts.httpBindAddr)
		if err != nil {
			logger.LogError(ctx, "http listen failed", err,
				"addr", opts.httpBindAddr)
			fmt.Fprintf(stderr, "redmatrix-server: http listen %s: %v\n", opts.httpBindAddr, err)
			// Listen 失败 → 取消 ctx 让 Relay 退出 + 等它结束
			relayWG.Wait()
			return 1
		}
		actualAddr := listener.Addr().String()

		srv := &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
		}
		if opts.onListening != nil {
			opts.onListening(actualAddr)
		}
		logger.Info("http server listening",
			"addr", actualAddr,
			"endpoints", []string{"/health", "/ready", "/metrics", idMount.path, tnMount.path, scMount.path},
		)

		serverErr := make(chan error, 1)
		go func() {
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErr <- err
			}
			close(serverErr)
		}()

		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received; closing http server",
				"reason", ctx.Err().Error())
		case err := <-serverErr:
			logger.LogError(ctx, "http server crashed", err)
			_ = srv.Close()
			return 1
		}

		shutdownCtx, cancelShutdown := context.WithTimeout(
			context.Background(), defaultShutdownTimeout)
		defer cancelShutdown()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.LogError(shutdownCtx, "http server shutdown error", err)
			relayWG.Wait()
			return 1
		}
		logger.Info("http server shutdown complete")

		// node_agent mTLS server（可空）也优雅关
		if err := nodeAgentSrv.shutdown(defaultShutdownTimeout); err != nil {
			logger.LogError(shutdownCtx, "node_agent shutdown error", err)
		} else if nodeAgentSrv != nil {
			logger.Info("node_agent shutdown complete")
		}

		// 等 Relay goroutine 退出（ctx 已取消触发优雅退出）
		relayWG.Wait()
		logger.Info("relay shutdown complete")
		// PR-S17-RACE：等 sweeper 退出（ctx 已 cancel）。在 pool.Close defer 前。
		<-sweeperDone
		logger.Info("sweeper shutdown complete")
		return 0
	}

	// 无 HTTP path（unit / boot integration 测试场景）：保留 scaffold 行为。
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
