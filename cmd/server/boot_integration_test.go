//go:build integration

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/testharness/esharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

// setRealStorageEnv 启 PG + Redis + ES 容器，覆盖 setValidEnv 的 127.0.0.1:1 占位
// 让 boot 完整 ping 通过。
func setRealStorageEnv(t *testing.T) (pg *pgharness.PG, rds *redisharness.Redis, esC *esharness.ES) {
	t.Helper()
	pgC := pgharness.Start(t)
	rdsC := redisharness.Start(t)
	esCC := esharness.Start(t)
	setValidEnv(t)
	t.Setenv("PG_DSN", pgC.AppDSN)
	t.Setenv("PG_DSN_MAINTENANCE", pgC.MaintenanceDSN)
	t.Setenv("REDIS_URL", rdsC.URL)
	t.Setenv("ES_URL", esCC.URL)
	return pgC, rdsC, esCC
}

// TestRun_FullSuccess 走真实 PG 容器，验证 boot 完整流水线（Open + Ping + 不带 migrate）。
//
// 用 `run`（非 runForTest），让生产路径真实执行：
//   - PG 探活 30s 超时
//   - 默认 MinConns 主动建连（容器响应快，不会卡）
func TestRun_FullSuccess(t *testing.T) {
	setRealStorageEnv(t)
	t.Setenv("PG_DSN_ADMIN", "")
	t.Setenv("RM_AUTO_MIGRATE", "false")

	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr)

	require.Equal(t, 0, code, "stderr=%s", stderr.String())
	assert.Empty(t, stderr.String())

	out := stdout.String()
	assert.Contains(t, out, "redmatrix-server starting")
	assert.Contains(t, out, "config loaded")
	assert.Contains(t, out, "pg pools ready")
	assert.Contains(t, out, "redis ready")
	assert.Contains(t, out, "es ready")
	assert.Contains(t, out, "scaffold boot complete")

	// 不应进入 migrate 路径
	assert.NotContains(t, out, "auto-migrate applied")
}

// TestRun_FullSuccessWithAutoMigrate 走 RM_AUTO_MIGRATE=true 路径，
// 验证 migrate.Up 落库后日志输出 "auto-migrate applied"。
func TestRun_FullSuccessWithAutoMigrate(t *testing.T) {
	pgC, _, _ := setRealStorageEnv(t)
	t.Setenv("PG_DSN_ADMIN", pgC.AdminDSN)
	t.Setenv("RM_AUTO_MIGRATE", "true")

	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr)

	require.Equal(t, 0, code, "stderr=%s", stderr.String())

	out := stdout.String()
	assert.Contains(t, out, "auto-migrate applied")
	assert.Contains(t, out, "redis ready")
	assert.Contains(t, out, "es ready")
	assert.Contains(t, out, "scaffold boot complete")

	// 摘要应标记 admin 已配置
	assert.Contains(t, out, `"db.pg_admin_configured":true`)
}

// TestRun_FullSuccessNoSecretLeak 真实 PG 路径下，再次断言摘要不泄漏密钥。
//
// 这与 unit 的 TestRunNoSecretLeakInBootSummary 互补：
//   - unit 测试在 PG 不可达分支验证（boot 早退）
//   - 集成测试在完整成功路径验证（boot 走完）
func TestRun_FullSuccessNoSecretLeak(t *testing.T) {
	setRealStorageEnv(t)

	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, run(&stdout, &stderr), "stderr=%s", stderr.String())

	out := stdout.String()

	// 关键不变量：成功路径下也不得泄漏任何密钥 / DSN 凭据原文
	assert.NotContains(t, out, testJWTSecret)
	assert.NotContains(t, out, testEncKey)
	assert.NotContains(t, out, testHMACKey)
	assert.NotContains(t, out, testBackupKey)
	// 容器密码 "app_test_pw" 不应泄漏（pg.Sanitize / redis.Sanitize 已脱敏）
	assert.NotContains(t, out, "app_test_pw")
	assert.NotContains(t, out, "maint_test_pw")
}

// TestRun_AutoMigrateAdminMissingWarns 验证 RM_AUTO_MIGRATE=true 但
// PG_DSN_ADMIN 缺失时不报错（Warn-skip 路径）。
func TestRun_AutoMigrateAdminMissingWarns(t *testing.T) {
	setRealStorageEnv(t)
	t.Setenv("PG_DSN_ADMIN", "")
	t.Setenv("RM_AUTO_MIGRATE", "true")

	var stdout, stderr bytes.Buffer
	require.Equal(t, 0, run(&stdout, &stderr))

	out := stdout.String()
	// Warn 行包含关键提示
	assert.Contains(t, out, "RM_AUTO_MIGRATE=true 但 PG_DSN_ADMIN 未配置")
	// 但 boot 仍成功
	assert.Contains(t, out, "scaffold boot complete")

	// 顺手验证 stderr 应空（warn 不入 stderr）
	assert.Equal(t, "", strings.TrimSpace(stderr.String()))
}
