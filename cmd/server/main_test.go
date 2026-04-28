package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	"github.com/ffff5sec/RedMatrix/internal/storage/redis"
)

// runForTest 包装 runWith，注入测试用的快速超时与不主动建连的池配置。
//
// PG / Redis 都以小池 + MinIdleConns=0 启动，避免不可达 URL 的后台重连拖死测试。
// PG ping 2s / Redis ping 1s 足够 ECONNREFUSED 反弹。
func runForTest(stdout, stderr io.Writer) int {
	return runWith(stdout, stderr, runOptions{
		pgPingTimeout:    2 * time.Second,
		redisPingTimeout: 1 * time.Second,
		migrateTimeout:   5 * time.Second,
		pgPoolOverride: func(cfg pg.Config) pg.Config {
			cfg.AppMaxConns = 2
			cfg.AppMinConns = 0
			cfg.MaintenanceMaxConns = 2
			cfg.MaintenanceMinConns = 0
			cfg.AdminMaxConns = 2
			return cfg
		},
		redisOverride: func(cfg redis.Config) redis.Config {
			cfg.PoolSize = 2
			cfg.MinIdleConns = 0
			return cfg
		},
	})
}

// 测试专用密钥（与 internal/config 测试中保持互异）。
var (
	testEncKey    = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xA1))
	testHMACKey   = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xB2))
	testBackupKey = base64.StdEncoding.EncodeToString(bytesOfLen(32, 0xC3))
	testJWTSecret = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@" // 64 chars
)

func bytesOfLen(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

// setValidEnv 注入一份能通过 config.Validate 的最小 env。
// 复用 t.Setenv 自动还原。注意：调用方不可使用 t.Parallel()。
//
// PG / Redis / MinIO host 全部指向 127.0.0.1:1（保留端口，必然 ECONNREFUSED），
// 让 PG ping 在毫秒级失败 → BOOTSTRAP_DB_UNREACHABLE，避免 DNS / 长连接 timeout
// 拖慢测试。完整 boot 成功路径由 testcontainers 集成测试覆盖（后续 PR）。
func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PG_DSN", "postgres://redmatrix_app:pw@127.0.0.1:1/redmatrix?sslmode=require")
	t.Setenv("PG_DSN_MAINTENANCE", "postgres://redmatrix_maintenance:pw@127.0.0.1:1/redmatrix?sslmode=require")
	t.Setenv("ES_URL", "http://127.0.0.1:1")
	t.Setenv("REDIS_URL", "redis://:pw@127.0.0.1:1/0")
	t.Setenv("MINIO_ENDPOINT", "127.0.0.1:1")
	t.Setenv("MINIO_PUBLIC_ENDPOINT", "minio.example.com:9000")
	t.Setenv("MINIO_ACCESS_KEY", "AKIA")
	t.Setenv("MINIO_SECRET_KEY", "secret")
	t.Setenv("PUBLIC_DOMAIN", "redmatrix.example.com")
	t.Setenv("PUBLIC_GRPC_ADDR", "grpc.example.com:9090")
	t.Setenv("PUBLIC_MINIO_ADDR", "minio.example.com:9000")
	t.Setenv("JWT_SECRET", testJWTSecret)
	t.Setenv("ENCRYPTION_KEY", testEncKey)
	t.Setenv("AUDIT_HMAC_KEY", testHMACKey)
	t.Setenv("BACKUP_KEY", testBackupKey)
	// AutoMigrate 默认 true，但 PG_DSN_ADMIN 留空 → migrate 跳过（仅 Warn）。
	// 若测试关心 admin 路径请单独设置。
	t.Setenv("RM_AUTO_MIGRATE", "false")
}

func TestRunPGUnreachable(t *testing.T) {
	// 全配置合法但 PG 不可达 → boot 应在 ping 阶段失败。
	setValidEnv(t)
	var stdout, stderr bytes.Buffer

	code := runForTest(&stdout, &stderr)

	assert.Equal(t, 2, code, "BOOTSTRAP_DB_UNREACHABLE 应映射 exit 2")
	assert.Contains(t, stderr.String(), "BOOTSTRAP_DB_UNREACHABLE")

	// stdout 应包含启动 + 配置摘要（在 ping 之前已输出）
	out := stdout.String()
	assert.Contains(t, out, "redmatrix-server starting")
	assert.Contains(t, out, "config loaded")
	// 不应到达 scaffold-complete 行（在 ping 之后）
	assert.NotContains(t, out, "scaffold boot complete")
}

func TestRunNoSecretLeakInBootSummary(t *testing.T) {
	setValidEnv(t)
	var stdout, stderr bytes.Buffer

	// 此测试不关心 exit code（PG 不可达必失败），只关心日志不泄漏密钥
	_ = runForTest(&stdout, &stderr)

	out := stdout.String()
	// 关键不变量：摘要输出不得包含任何密钥 / DSN 凭据 / MinIO 凭据原文
	assert.NotContains(t, out, testJWTSecret, "JWT secret leaked to stdout")
	assert.NotContains(t, out, testEncKey, "ENCRYPTION_KEY leaked")
	assert.NotContains(t, out, testHMACKey, "AUDIT_HMAC_KEY leaked")
	assert.NotContains(t, out, testBackupKey, "BACKUP_KEY leaked")
	assert.NotContains(t, out, "AKIA", "MINIO_ACCESS_KEY leaked")
	assert.NotContains(t, out, "redmatrix_app:pw", "PG DSN with credentials leaked")
	assert.NotContains(t, out, "redis://:pw", "Redis URL with credentials leaked")

	// 但应包含长度（验证非空）
	assert.Contains(t, out, "crypto.jwt_secret_len")
	assert.Contains(t, out, "crypto.encryption_key_bytes")
}

func TestRunMissingRequiredEnv(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PG_DSN", "")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_CONFIG_INVALID")
	assert.Contains(t, stderr.String(), "PG_DSN")
}

func TestRunInvalidJWTSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("JWT_SECRET", "tooshort")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_CRYPTO_INVALID")
}

func TestRunInvalidBase64Key(t *testing.T) {
	setValidEnv(t)
	t.Setenv("ENCRYPTION_KEY", "not-base64!!!@@@")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_CRYPTO_INVALID")
	assert.Contains(t, stderr.String(), "ENCRYPTION_KEY")
}

func TestRunKeyReuse(t *testing.T) {
	setValidEnv(t)
	t.Setenv("BACKUP_KEY", testEncKey) // 与 ENCRYPTION_KEY 相同

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_KEY_REUSE_FORBIDDEN")
}

func TestRunSslDisableRejected(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PG_DSN", "postgres://redmatrix_app:pw@pg:5432/redmatrix?sslmode=disable")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_CONFIG_INVALID")
	assert.Contains(t, stderr.String(), "PG_DSN")
}

func TestRunInvalidLogLevelFromConfig(t *testing.T) {
	setValidEnv(t)
	t.Setenv("LOG_LEVEL", "verbose")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)

	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "BOOTSTRAP_CONFIG_INVALID")
}

func TestFailExitCodeBootstrap(t *testing.T) {
	// 直接断言映射；用一个真实的 BOOTSTRAP_* 错误穿过路径
	setValidEnv(t)
	t.Setenv("JWT_SECRET", "x")

	var stderr bytes.Buffer
	code := runForTest(io.Discard, &stderr)
	assert.Equal(t, 2, code, "BOOTSTRAP_* errors must map to exit 2")
}

func TestStderrFormat(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PG_DSN", "")

	var stderr bytes.Buffer
	_ = runForTest(io.Discard, &stderr)

	// stderr 应是单行 "redmatrix-server: <code>: <msg>" 格式
	line := strings.TrimSpace(stderr.String())
	assert.True(t, strings.HasPrefix(line, "redmatrix-server: "), "stderr=%q", line)
}
