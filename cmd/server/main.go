// Command redmatrix-server 是 RedMatrix 平台中心的入口。
//
// 当前阶段（scaffold + boot 串联）：
//   1. 加载 env 配置（internal/config）
//   2. 静态 fail-fast 校验（密钥强度 / 三密钥互异 / PG sslmode / role 名 / log 取值）
//   3. 初始化日志门面（internal/platform/log）并 SetDefault
//   4. 输出版本 + 配置摘要（绝不打印密钥 / 凭据）
//   5. 退出 0
//
// 下一阶段（待 PR）：连通性检查（PG / ES / Redis / MinIO ping） → ConnectRPC
// handler 注册 → 监听 / SIGTERM 优雅退出。
//
// 退出码（与 docs/LLD/40-deployment-detail.md §2.5 / §9.6 对齐）：
//   0 — 成功
//   1 — 运行时失败（连通性 / SIGABRT 等；当前 scaffold 阶段未触发）
//   2 — bootstrap fatal（必填缺失 / 密钥不合法 / 配置取值非法等）
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/version"
)

func main() {
	os.Exit(run(os.Stdout, os.Stderr))
}

// run 是可测试入口。返回 process exit code。
func run(stdout, stderr io.Writer) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}

	logger, err := log.New(log.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
		Output: stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "redmatrix-server: %v\n", err)
		return failExitCode(err)
	}
	log.SetDefault(logger)

	logger.Info("redmatrix-server starting",
		"version", version.Version,
		"commit", version.Commit,
		"build_date", version.BuildDate,
		"env", cfg.Env,
	)
	logBootSummary(logger, cfg)

	// TODO(scaffold): 连通性检查 → 注册 handler → 监听端口 → 等 SIGTERM。
	logger.Info("scaffold boot complete; exiting until RPC wiring lands")
	return 0
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
// 仅打印长度 / 字节数辅助验证非空。
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
