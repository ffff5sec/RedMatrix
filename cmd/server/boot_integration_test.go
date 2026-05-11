//go:build integration

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	_ "github.com/jackc/pgx/v5/stdlib"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	identityv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1/identityv1connect"
	"github.com/ffff5sec/RedMatrix/internal/platform/health"
	"github.com/ffff5sec/RedMatrix/internal/storage/migrate"
	rmminio "github.com/ffff5sec/RedMatrix/internal/storage/minio"
	"github.com/ffff5sec/RedMatrix/internal/testharness/esharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/minioharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/pgharness"
	"github.com/ffff5sec/RedMatrix/internal/testharness/redisharness"
)

// readCaptchaFromRedis 直接从 Redis 取 captcha 答案（仅集成测试用；
// 生产用户从图片 OCR）。Key 格式与 policy.NewRedisCaptcha 对齐。
func readCaptchaFromRedis(t *testing.T, captchaID string) string {
	t.Helper()
	url := os.Getenv("REDIS_URL")
	require.NotEmpty(t, url)
	opt, err := goredis.ParseURL(url)
	require.NoError(t, err)
	c := goredis.NewClient(opt)
	defer func() { _ = c.Close() }()

	ans, err := c.Get(context.Background(),
		"global:captcha:"+captchaID).Result()
	require.NoError(t, err)
	require.NotEmpty(t, ans)
	return ans
}

// setRealStorageEnv 启 PG + Redis + ES + MinIO 四容器，覆盖 setValidEnv 的
// 127.0.0.1:1 占位让 boot 完整 ping 通过：
//   - PG：跑 migrate.Up 让所有 schema（含 outbox_events）落库。Relay goroutine
//     启动后会扫 outbox 表，缺表则崩。
//   - MinIO：提前 EnsureBuckets 9 个让 boot 的 VerifyBuckets 通过。
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// PG schema：所有迁移落库（包含 0003 outbox_events，Relay 需要）
	db, err := sql.Open("pgx", pgC.AdminDSN)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, migrate.Up(ctx, db))

	// 9 bucket 预建（生产由 minio-bootstrap job 做；这里在测试 helper 中等价完成）。
	mioClient, err := rmminio.Open(ctx, rmminio.Config{
		Endpoint:  mioC.Endpoint,
		AccessKey: mioC.AccessKey,
		SecretKey: mioC.SecretKey,
	})
	require.NoError(t, err)
	defer func() { _ = mioClient.Close() }()
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
	code := runWith(&stdout, &stderr, runOptions{})

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
	code := runWith(&stdout, &stderr, runOptions{})

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
	require.Equal(t, 0, runWith(&stdout, &stderr, runOptions{}), "stderr=%s", stderr.String())

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
	require.Equal(t, 0, runWith(&stdout, &stderr, runOptions{}))

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
	// Bootstrap admin：固定密码便于 Login smoke 复用
	const bootstrapPwd = "TestBootstrapAdminPwd1!"
	t.Setenv("ADMIN_BOOTSTRAP_PASSWORD", bootstrapPwd)
	// PR-S20+：跳 mTLS NodeAgentServer——本测试只验 HTTP /health /ready；
	// setValidEnv 默认设 grpc.example.com:9090 DNS 不通 → listen 必失败 →
	// server fatal exit → HTTP 永远启不起来。空字串让 startNodeAgentServer skip。
	t.Setenv("PUBLIC_GRPC_ADDR", "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan string, 1)
	codeCh := make(chan int, 1)

	// 提到外部供 cancel 后断言 relay 启停日志。读取在 codeCh receive 之后
	// （channel happens-before 保证写完成）。
	var stdout, stderr bytes.Buffer

	go func() {
		code := runWith(&stdout, &stderr, runOptions{
			ctx:          ctx,
			httpBindAddr: "127.0.0.1:0",
			onListening: func(addr string) {
				addrCh <- addr
			},
		})
		codeCh <- code
	}()

	var addr string
	select {
	case addr = <-addrCh:
	case <-time.After(5 * time.Minute):
		// GitHub Actions runner 启 ES container（JVM cluster green ~90s）+
		// PG/Redis/MinIO 串行 ping + PR-S17/S18 boot 多 metricsscan/bus/outbox/
		// scheduler/sweeper 步骤。本机 / 已 warm 通常 5-10s，CI 偶现 200s+。
		cancel()
		// PR-S20+：超时时打 server stderr/stdout 让 CI 知道卡在哪
		t.Logf("=== server stdout（截断到 4KB） ===\n%.4096s", stdout.String())
		t.Logf("=== server stderr（截断到 4KB） ===\n%.4096s", stderr.String())
		t.Fatal("HTTP server 未在 5 分钟内监听（看上面 stderr 找卡在哪步）")
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

	// /metrics → 200 + 含 redmatrix_build_info + go_goroutines
	t.Run("metrics", func(t *testing.T) {
		resp, err := http.Get("http://" + addr + "/metrics")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		bodyBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		body := string(bodyBytes)
		assert.Contains(t, body, "redmatrix_build_info")
		assert.Contains(t, body, "go_goroutines")
		assert.Contains(t, body, "process_resident_memory_bytes")
	})

	// IdentityService.GetCaptcha smoke：调真实 ConnectRPC，验 RPC 路径接通
	// + Captcha policy 真访问 Redis（生产闭环路径）
	t.Run("identity_get_captcha", func(t *testing.T) {
		client := identityv1connect.NewIdentityServiceClient(
			http.DefaultClient,
			"http://"+addr,
		)
		res, err := client.GetCaptcha(context.Background(),
			connect.NewRequest(&identityv1.GetCaptchaRequest{}))
		require.NoError(t, err)
		assert.NotEmpty(t, res.Msg.GetCaptchaId())
		require.NotEmpty(t, res.Msg.GetImagePng())

		// PNG magic header
		png := res.Msg.GetImagePng()
		require.True(t, len(png) > 8)
		assert.Equal(t, byte(0x89), png[0])
		assert.Equal(t, byte(0x50), png[1])
	})

	// IdentityService.Login smoke：用 bootstrap 写入的 SuperAdmin 凭据登录。
	// 验证：Bootstrap 真落库 + Login 走完密码校验 / 写 session / 签 JWT 全链路。
	//
	// 注意：默认 captcha policy AlwaysShow=true → Login 会要 captcha。
	// 但本测试不带 captcha 时 server 应返 AUTH_CAPTCHA_REQUIRED；先验该错码，
	// 再带 captcha 完整跑一遍。
	t.Run("identity_login_bootstrap_admin", func(t *testing.T) {
		client := identityv1connect.NewIdentityServiceClient(
			http.DefaultClient,
			"http://"+addr,
		)

		// 1. 不带 captcha → 期望 AUTH_CAPTCHA_REQUIRED
		_, err := client.Login(context.Background(),
			connect.NewRequest(&identityv1.LoginRequest{
				Username: "admin",
				Password: bootstrapPwd,
			}))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err),
			"AlwaysShow=true 时缺 captcha 必返 AUTH_CAPTCHA_REQUIRED")

		// 2. 取 captcha
		capRes, err := client.GetCaptcha(context.Background(),
			connect.NewRequest(&identityv1.GetCaptchaRequest{}))
		require.NoError(t, err)

		// 直接从 Redis 读答案（用例需求；前端用户从图片 OCR）
		captchaAnswer := readCaptchaFromRedis(t, capRes.Msg.GetCaptchaId())

		// 3. 带 captcha 登录
		captchaID := capRes.Msg.GetCaptchaId()
		loginRes, err := client.Login(context.Background(),
			connect.NewRequest(&identityv1.LoginRequest{
				Username:      "admin",
				Password:      bootstrapPwd,
				CaptchaId:     &captchaID,
				CaptchaAnswer: &captchaAnswer,
			}))
		require.NoError(t, err)
		assert.NotEmpty(t, loginRes.Msg.GetAccessToken(), "Login 应返 JWT")
		require.NotNil(t, loginRes.Msg.GetUser())
		assert.Equal(t, "admin", loginRes.Msg.GetUser().GetUsername())
		assert.Equal(t, "SUPER_ADMIN", loginRes.Msg.GetUser().GetRole())
		assert.True(t, loginRes.Msg.GetMustChangePassword(),
			"bootstrap admin 首登必须要求改密")

		// 4. ChangePassword 闭合 must_change_password 流程
		const newPwd = "ChangedFromBootstrap1!"
		jwt := loginRes.Msg.GetAccessToken()
		cpReq := connect.NewRequest(&identityv1.ChangePasswordRequest{
			CurrentPassword: bootstrapPwd,
			NewPassword:     newPwd,
		})
		cpReq.Header().Set("Authorization", "Bearer "+jwt)
		cpRes, err := client.ChangePassword(context.Background(), cpReq)
		require.NoError(t, err)
		assert.True(t, cpRes.Msg.GetAllSessionsRevoked(),
			"ChangePassword 必须 tv++ → all_sessions_revoked")

		// 5. 旧 JWT 失效（GetCurrentUser 应返 AUTH_TOKEN_VERSION_MISMATCH）
		gcuReq := connect.NewRequest(&identityv1.GetCurrentUserRequest{})
		gcuReq.Header().Set("Authorization", "Bearer "+jwt)
		_, err = client.GetCurrentUser(context.Background(), gcuReq)
		require.Error(t, err, "改密后旧 JWT 应失效")

		// 6. 用新密码再登录（must_change_password 应已为 false）
		cap2, err := client.GetCaptcha(context.Background(),
			connect.NewRequest(&identityv1.GetCaptchaRequest{}))
		require.NoError(t, err)
		ans2 := readCaptchaFromRedis(t, cap2.Msg.GetCaptchaId())
		cap2ID := cap2.Msg.GetCaptchaId()
		loginRes2, err := client.Login(context.Background(),
			connect.NewRequest(&identityv1.LoginRequest{
				Username:      "admin",
				Password:      newPwd,
				CaptchaId:     &cap2ID,
				CaptchaAnswer: &ans2,
			}))
		require.NoError(t, err)
		assert.NotEmpty(t, loginRes2.Msg.GetAccessToken())
		assert.False(t, loginRes2.Msg.GetMustChangePassword(),
			"改密后 must_change_password 应清空")
	})

	// User CRUD smoke：SA 创建 PA → 列出 → PA 用临时密码登录 → must_change=true
	t.Run("identity_user_crud", func(t *testing.T) {
		client := identityv1connect.NewIdentityServiceClient(
			http.DefaultClient,
			"http://"+addr,
		)

		// SA 登录拿 JWT（前面 ChangePassword 已改密 → 用新密码）
		const newAdminPwd = "ChangedFromBootstrap1!"
		capX, err := client.GetCaptcha(context.Background(),
			connect.NewRequest(&identityv1.GetCaptchaRequest{}))
		require.NoError(t, err)
		ansX := readCaptchaFromRedis(t, capX.Msg.GetCaptchaId())
		capXID := capX.Msg.GetCaptchaId()
		saLogin, err := client.Login(context.Background(),
			connect.NewRequest(&identityv1.LoginRequest{
				Username:      "admin",
				Password:      newAdminPwd,
				CaptchaId:     &capXID,
				CaptchaAnswer: &ansX,
			}))
		require.NoError(t, err)
		saJWT := saLogin.Msg.GetAccessToken()

		// CreateUser：服务端生成临时密码
		// 与 tenancy.DefaultAccountID 保持一致：bootstrap 期 ensure 的默认 account
		const tenantID = "00000000-0000-0000-0000-000000000001"
		cuReq := connect.NewRequest(&identityv1.CreateUserRequest{
			Username: "alice_pa",
			Email:    "alice@example.com",
			Role:     "PROJECT_ADMIN",
			TenantId: tenantID,
		})
		cuReq.Header().Set("Authorization", "Bearer "+saJWT)
		cuRes, err := client.CreateUser(context.Background(), cuReq)
		require.NoError(t, err)
		assert.NotEmpty(t, cuRes.Msg.GetTemporaryPassword(), "返临时密码")
		require.NotNil(t, cuRes.Msg.GetUser())
		newUID := cuRes.Msg.GetUser().GetId()
		assert.Equal(t, "alice_pa", cuRes.Msg.GetUser().GetUsername())
		assert.Equal(t, "PROJECT_ADMIN", cuRes.Msg.GetUser().GetRole())
		tempPwd := cuRes.Msg.GetTemporaryPassword()

		// ListUsers（SA 可读）：能看到 admin + alice_pa
		luReq := connect.NewRequest(&identityv1.ListUsersRequest{})
		luReq.Header().Set("Authorization", "Bearer "+saJWT)
		luRes, err := client.ListUsers(context.Background(), luReq)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, luRes.Msg.GetTotal(), int32(2))

		// alice_pa 用临时密码登录 → must_change=true
		capPA, err := client.GetCaptcha(context.Background(),
			connect.NewRequest(&identityv1.GetCaptchaRequest{}))
		require.NoError(t, err)
		ansPA := readCaptchaFromRedis(t, capPA.Msg.GetCaptchaId())
		capPAID := capPA.Msg.GetCaptchaId()
		paLogin, err := client.Login(context.Background(),
			connect.NewRequest(&identityv1.LoginRequest{
				Username:      "alice_pa",
				Password:      tempPwd,
				CaptchaId:     &capPAID,
				CaptchaAnswer: &ansPA,
			}))
		require.NoError(t, err)
		assert.True(t, paLogin.Msg.GetMustChangePassword(),
			"新建用户首登必须强制改密")

		// SA 调 ForceLogout 让 alice_pa 的 JWT 失效
		flReq := connect.NewRequest(&identityv1.ForceLogoutRequest{Id: newUID})
		flReq.Header().Set("Authorization", "Bearer "+saJWT)
		_, err = client.ForceLogout(context.Background(), flReq)
		require.NoError(t, err)

		// alice_pa 旧 JWT 应失效
		gcuPA := connect.NewRequest(&identityv1.GetCurrentUserRequest{})
		gcuPA.Header().Set("Authorization", "Bearer "+paLogin.Msg.GetAccessToken())
		_, err = client.GetCurrentUser(context.Background(), gcuPA)
		require.Error(t, err, "ForceLogout 后旧 JWT 应失效")

		// PA 试图调 CreateUser → 角色不足
		cu2 := connect.NewRequest(&identityv1.CreateUserRequest{
			Username: "evil", Email: "x@example.com", Role: "PROJECT_ADMIN",
			TenantId: tenantID,
		})
		// 这个 JWT 已被 ForceLogout 失效；用刚 ForceLogout 之前的 JWT 测 authz 不行
		// 改用 SA JWT 反向测：SA 角色调 ListUsers OK，PA 角色调 CreateUser 该被拒
		// 由于 PA 现在登录不了（ForceLogout 后 tv++），跳过 PA→拒 路径——
		// 单元测试已覆盖该 case；smoke 不重复。
		_ = cu2
	})

	// 触发优雅退出
	cancel()

	select {
	case code := <-codeCh:
		assert.Equal(t, 0, code, "ctx 取消后 runWith 应优雅返回 0")
	case <-time.After(15 * time.Second):
		t.Fatal("runWith 未在 15s 内退出")
	}

	// codeCh receive 之后 goroutine 已退出，安全读取 stdout/stderr
	out := stdout.String()
	t.Logf("runWith stdout:\n%s", out)
	if stderr.Len() > 0 {
		t.Logf("runWith stderr:\n%s", stderr.String())
	}

	// Relay 启停日志（与 cmd/server boot 流水线对齐）
	assert.Contains(t, out, "relay starting", "Relay 应在 HTTP server 之前启动")
	assert.Contains(t, out, "relay stopping", "ctx 取消应触发 relay stopping")
	assert.Contains(t, out, "relay shutdown complete", "runWith 退出前 relay 应完整退出")
}
