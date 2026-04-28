//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/platform/health"
	rmminio "github.com/ffff5sec/RedMatrix/internal/storage/minio"
	"github.com/ffff5sec/RedMatrix/internal/testharness/esharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/minioharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

// setRealStorageEnv 启 PG + Redis + ES + MinIO 四容器，覆盖 setValidEnv 的
// 127.0.0.1:1 占位让 boot 完整 ping 通过。MinIO 上提前 EnsureBuckets 9 个，
// 让 boot 的 VerifyBuckets 通过。
func setRealStorageEnv(t *testing.T) (
	pg *pgharness.PG,
	rds *redisharness.Redis,
	esC *esharness.ES,
	mio *minioharness.MinIO,
) {
	t.Helper()
	pgC := pgharness.Start(t)
	rdsC := redisharness.Start(t)
	esCC := esharness.Start(t)
	mioC := minioharness.Start(t)

	// 9 bucket 预建（生产由 minio-bootstrap job 做；这里在测试 helper 中等价完成）。
	mioClient, err := rmminio.Open(context.Background(), rmminio.Config{
		Endpoint:  mioC.Endpoint,
		AccessKey: mioC.AccessKey,
		SecretKey: mioC.SecretKey,
	})
	require.NoError(t, err)
	defer func() { _ = mioClient.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, mioClient.EnsureBuckets(ctx, rmminio.RequiredBuckets, ""))

	setValidEnv(t)
	t.Setenv("PG_DSN", pgC.AppDSN)
	t.Setenv("PG_DSN_MAINTENANCE", pgC.MaintenanceDSN)
	t.Setenv("REDIS_URL", rdsC.URL)
	t.Setenv("ES_URL", esCC.URL)
	t.Setenv("MINIO_ENDPOINT", mioC.Endpoint)
	t.Setenv("MINIO_ACCESS_KEY", mioC.AccessKey)
	t.Setenv("MINIO_SECRET_KEY", mioC.SecretKey)
	return pgC, rdsC, esCC, mioC
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
	assert.Contains(t, out, "minio ready")
	assert.Contains(t, out, `"buckets_verified":true`)
	assert.Contains(t, out, "scaffold boot complete")

	// 不应进入 migrate 路径
	assert.NotContains(t, out, "auto-migrate applied")
}

// TestRun_FullSuccessWithAutoMigrate 走 RM_AUTO_MIGRATE=true 路径，
// 验证 migrate.Up 落库后日志输出 "auto-migrate applied"。
func TestRun_FullSuccessWithAutoMigrate(t *testing.T) {
	pgC, _, _, _ := setRealStorageEnv(t)
	t.Setenv("PG_DSN_ADMIN", pgC.AdminDSN)
	t.Setenv("RM_AUTO_MIGRATE", "true")

	var stdout, stderr bytes.Buffer
	code := run(&stdout, &stderr)

	require.Equal(t, 0, code, "stderr=%s", stderr.String())

	out := stdout.String()
	assert.Contains(t, out, "auto-migrate applied")
	assert.Contains(t, out, "redis ready")
	assert.Contains(t, out, "es ready")
	assert.Contains(t, out, "minio ready")
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

// TestRun_HTTPHealthEndpoints 启 4 容器 + httpBindAddr=":0" 让 OS 选端口，
// 等 onListening 回传地址后 hit /health + /ready 验证响应。
// 然后 cancel ctx 让 server 优雅退出。
func TestRun_HTTPHealthEndpoints(t *testing.T) {
	setRealStorageEnv(t)
	t.Setenv("RM_AUTO_MIGRATE", "false")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	codeCh := make(chan int, 1)

	go func() {
		var stdout, stderr bytes.Buffer
		code := runWith(&stdout, &stderr, runOptions{
			ctx:          ctx,
			httpBindAddr: "127.0.0.1:0",
			onListening: func(addr string) {
				addrCh <- addr
			},
		})
		t.Logf("runWith stdout:\n%s", stdout.String())
		if stderr.Len() > 0 {
			t.Logf("runWith stderr:\n%s", stderr.String())
		}
		codeCh <- code
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(2 * time.Minute):
		cancel()
		t.Fatal("HTTP server 未在 2 分钟内监听")
	}

	t.Logf("HTTP server listening at http://%s", addr)

	// /health → 200 + {"status":"ok"}
	t.Run("liveness", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var body map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		assert.Equal(t, "ok", body["status"])
	})

	// /ready → 200 + 4 个 probe 全 OK
	t.Run("readiness", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/ready")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"4 容器都活着 readiness 应 200")

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		t.Logf("/ready body: %s", bodyBytes)

		var rep health.Report
		require.NoError(t, json.Unmarshal(bodyBytes, &rep))
		assert.Equal(t, health.StatusOK, rep.Status)
		assert.Len(t, rep.Checks, 4, "pg / redis / es / minio 四个 probe")
		for name, r := range rep.Checks {
			assert.Truef(t, r.OK, "probe %s 应 OK，error=%q", name, r.Error)
		}
	})

	// 触发优雅退出
	cancel()

	select {
	case code := <-codeCh:
		assert.Equal(t, 0, code, "ctx 取消后 runWith 应优雅返回 0")
	case <-time.After(15 * time.Second):
		t.Fatal("runWith 未在 15s 内退出")
	}
}
