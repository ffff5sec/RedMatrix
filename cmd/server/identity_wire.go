package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1/identityv1connect"
	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/identity/crypto"
	"github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	rmredis "github.com/ffff5sec/RedMatrix/internal/storage/redis"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
	tenancyhandler "github.com/ffff5sec/RedMatrix/internal/tenancy/handler"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
)

// identityHandlerMount 是 buildIdentityMount 返回的挂载信息：path + http.Handler。
type identityHandlerMount struct {
	path    string
	handler http.Handler
}

// buildIdentityMount 装配 identity 模块全栈，返回 ConnectRPC mount + AuthService。
//
// 返 authSvc 让 buildTenancyMount 等下游模块复用，避免重建 lockout/captcha 等依赖。
//
// 依赖（按顺序构造）：
//  1. Repos（pgxpool.App 池；后续 RLS 落地后由 tenancy interceptor 注入 session var）
//  2. JWT 服务（HS256 + cfg.Crypto.JWTSecret）
//  3. Lockout（Redis 滑窗；fail-open）
//  4. Captcha（Redis；MVP always_show=true）
//  5. AuthService（组合 1-4）
//  6. handler.Handler（适配 ConnectRPC）
//  7. identityv1connect.NewIdentityServiceHandler 产出 (path, http.Handler)
func buildIdentityMount(pool *pg.Pool, rds *rmredis.Client, jwtSecret string) (*identityHandlerMount, auth.Service, *handler.Handler, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildIdentityMount: pg.Pool.App 不能为 nil")
	}
	if rds == nil || rds.Client == nil {
		return nil, nil, nil, errx.New(errx.ErrInternal, "buildIdentityMount: redis client 不能为 nil")
	}

	users := repo.NewPG(pool.App)
	sessions := repo.NewSessionPG(pool.App)
	keys := repo.NewAPIKeyPG(pool.App)

	jwtSvc, err := crypto.NewService(jwtSecret, 0) // 0 = 默认 12h
	if err != nil {
		return nil, nil, nil, err
	}

	lockout, err := policy.NewRedis(rds.Client, policy.DefaultConfig())
	if err != nil {
		return nil, nil, nil, err
	}

	captcha, err := policy.NewRedisCaptcha(rds.Client, policy.DefaultCaptchaConfig())
	if err != nil {
		return nil, nil, nil, err
	}

	authSvc, err := auth.New(users, sessions, keys, jwtSvc, lockout, captcha)
	if err != nil {
		return nil, nil, nil, err
	}

	idHandler, err := handler.New(authSvc, captcha)
	if err != nil {
		return nil, nil, nil, err
	}

	path, h := identityv1connect.NewIdentityServiceHandler(idHandler)
	return &identityHandlerMount{path: path, handler: h}, authSvc, idHandler, nil
}

// buildTenancyMount 装配 tenancy 模块（Project CRUD + Node + Token + Cert），
// 返回 ConnectRPC mount + service（NodeAgent 端点复用 svc 共享 mTLS 配置一致性）。
//
// 依赖：pgxpool.App + identity Auth Service + 节点签发用 CA。
// PR-S41: auditHook 可空；不空则 wire 进 handler.WithAudit，项目/成员变更落 audit。
func buildTenancyMount(pool *pg.Pool, authSvc auth.Service, ca *pki.CA, auditHook audithook.Hook, endpoints tenancyhandler.Endpoints) (*identityHandlerMount, tenancy.Service, error) {
	if pool == nil || pool.App == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildTenancyMount: pg.Pool.App 不能为 nil")
	}
	if authSvc == nil {
		return nil, nil, errx.New(errx.ErrInternal, "buildTenancyMount: authSvc 不能为 nil")
	}

	projects := tenancyrepo.NewProjectPG(pool.App)
	members := tenancyrepo.NewProjectMemberPG(pool.App)
	nodes := tenancyrepo.NewNodePG(pool.App)
	allowed := tenancyrepo.NewAllowedNodesPG(pool.App)
	tokens := tenancyrepo.NewRegistrationTokenPG(pool.App)
	certs := tenancyrepo.NewNodeCertificatePG(pool.App)
	users := repo.NewPG(pool.App) // 复用 identity 的 user repo（同 pool）
	svc, err := tenancy.NewService(projects, members, nodes, allowed, tokens, certs, users, ca)
	if err != nil {
		return nil, nil, err
	}
	h, err := tenancyhandler.New(svc, authSvc)
	if err != nil {
		return nil, nil, err
	}
	if auditHook != nil {
		h.WithAudit(auditHook)
	}
	h.WithEndpoints(endpoints) // PR-S73 注入 server URL / mTLS endpoint，CreateRegistrationToken 响应里带上
	path, hh := tenancyv1connect.NewTenancyServiceHandler(h)
	return &identityHandlerMount{path: path, handler: hh}, svc, nil
}

// computeAgentEndpoints PR-S73：根据 cfg.Public + 监听端口推导 agent 接入
// 端点。优先级：
//
//	server URL    = cfg.Public.Domain ? scheme://Domain : "http://127.0.0.1<httpBindAddr>"
//	node agent URL = scheme://cfg.Public.GRPCAddr（必填，否则空串）
//	mtls SAN      = host(GRPCAddr) 或 cfg.Public.Domain 之一
//
// 不需 caller 提供；UI 拿到后拼一键安装命令。
func computeAgentEndpoints(cfg *config.Config, httpBindAddr string) tenancyhandler.Endpoints {
	if cfg == nil {
		return tenancyhandler.Endpoints{}
	}
	out := tenancyhandler.Endpoints{}
	// server URL：dev 没设 Domain 时 fallback localhost + http
	domain := cfg.Public.Domain
	if domain == "" || domain == "localhost" {
		port := httpBindAddr
		if port == "" {
			port = ":8080"
		}
		// 把 ":8080" 转 "127.0.0.1:8080"
		if strings.HasPrefix(port, ":") {
			port = "127.0.0.1" + port
		}
		out.ServerURL = "http://" + port
	} else {
		out.ServerURL = "https://" + domain
	}
	// node agent URL：永远走 https://+ GRPCAddr（mTLS）
	if cfg.Public.GRPCAddr != "" {
		out.NodeAgentURL = "https://" + cfg.Public.GRPCAddr
		// mTLS SAN：host 部分
		if i := strings.LastIndex(cfg.Public.GRPCAddr, ":"); i > 0 {
			out.MTLSServerName = cfg.Public.GRPCAddr[:i]
		} else {
			out.MTLSServerName = cfg.Public.GRPCAddr
		}
	}
	return out
}

// ensureCA 启动期保证根 CA 落地：
//
//	$DATA_DIR/pki/ca.crt + ca.key（PEM）；缺则生成 + 0600 写盘。
//
// 路径优先级：env PKI_CA_CERT_PATH / PKI_CA_KEY_PATH > env DATA_DIR/pki/ >
// "./data/pki/"。运维可用 env 替换外部签发的 CA。
func ensureCA(logger *log.Logger) (*pki.CA, error) {
	certPath, keyPath := caPaths()

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		ca, err := pki.LoadCAPEM(certPEM, keyPEM)
		if err != nil {
			return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: 加载已存在 CA 失败").
				WithFields("cert_path", certPath, "key_path", keyPath)
		}
		logger.Info("tenancy CA loaded", "cert_path", certPath)
		return ca, nil
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		// 首启：生成 + 持久
	default:
		// 半状态（只缺一个）= 致命：可能上次写崩
		return nil, errx.New(errx.ErrInternal,
			"ensureCA: cert/key 状态不一致，需手动清理或恢复").
			WithFields("cert_path", certPath, "key_path", keyPath,
				"cert_err", fmt.Sprint(certErr), "key_err", fmt.Sprint(keyErr))
	}

	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: 生成 CA 失败")
	}
	newCertPEM, newKeyPEM, err := pki.MarshalCAPEM(ca)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: marshal CA 失败")
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: 创建 PKI 目录失败").
			WithFields("dir", filepath.Dir(certPath))
	}
	if err := os.WriteFile(certPath, newCertPEM, 0o600); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: 写 CA cert 失败").
			WithFields("path", certPath)
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0o600); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "ensureCA: 写 CA key 失败").
			WithFields("path", keyPath)
	}
	logger.Info("tenancy CA generated", "cert_path", certPath, "key_path", keyPath)
	return ca, nil
}

// caPaths 解析 CA cert/key 落盘位置。
func caPaths() (certPath, keyPath string) {
	certPath = os.Getenv("PKI_CA_CERT_PATH")
	keyPath = os.Getenv("PKI_CA_KEY_PATH")
	if certPath != "" && keyPath != "" {
		return certPath, keyPath
	}
	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	if certPath == "" {
		certPath = filepath.Join(dataDir, "pki", "ca.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(dataDir, "pki", "ca.key")
	}
	return certPath, keyPath
}

// runTenancyBootstrap 启动期落地默认 account（幂等）。
//
// 必须在 runBootstrap（identity admin）之前调：identity 首启 SA 与 tenant 无关
// （tenant_id=NULL），但创建后续 PA/TA 用户时 caller 需要默认 account ID
// （前端 / API 用 tenancy.DefaultAccountID 硬编码）。
func runTenancyBootstrap(
	ctx context.Context,
	logger *log.Logger,
	pool *pg.Pool,
) error {
	if pool == nil || pool.Maintenance == nil {
		return errx.New(errx.ErrInternal, "runTenancyBootstrap: pool.Maintenance 不能为 nil")
	}
	accounts := tenancyrepo.NewAccountPG(pool.Maintenance)

	res, err := tenancy.Bootstrap(ctx, accounts, tenancy.BootstrapConfig{})
	if err != nil {
		logger.LogError(ctx, "tenancy bootstrap failed", err)
		return err
	}
	if res.Created {
		logger.Info("tenancy bootstrap created default account",
			"id", res.Account.ID,
			"slug", res.Account.Slug,
		)
	} else {
		logger.Info("tenancy bootstrap skipped (default account exists)",
			"id", res.Account.ID,
			"slug", res.Account.Slug,
		)
	}
	return nil
}

// runBootstrap 在 HTTP server 启动前落地首个 SuperAdmin（幂等）。
//
// 用 pool.Maintenance（绕 RLS）：SuperAdmin tenant_id=NULL，App 池启 RLS 后无法直插。
//
// 副作用：
//   - 第一次启动 + ADMIN_BOOTSTRAP_PASSWORD 留空 → 生成的随机密码 + 警告横幅
//     一次性写 stdout（仅本次进程；不入日志结构化字段防被 log 收集）
//   - 已存在 SuperAdmin → info 日志 "skipped"，本次配置即使设了 password 也忽略
//   - 任何失败 → 返错给 caller（main.go failExitCode）
func runBootstrap(
	ctx context.Context,
	logger *log.Logger,
	stdout io.Writer,
	pool *pg.Pool,
	cfg *config.Config,
) error {
	if pool == nil || pool.Maintenance == nil {
		return errx.New(errx.ErrInternal, "runBootstrap: pool.Maintenance 不能为 nil")
	}
	users := repo.NewPG(pool.Maintenance)

	res, err := identity.Bootstrap(ctx, users, identity.BootstrapConfig{
		Username: cfg.Bootstrap.Username,
		Email:    cfg.Bootstrap.Email,
		Password: cfg.Bootstrap.Password,
	})
	if err != nil {
		logger.LogError(ctx, "bootstrap admin failed", err)
		return err
	}

	switch {
	case !res.Created:
		logger.Info("bootstrap admin skipped (SuperAdmin 已存在)",
			"username", cfg.Bootstrap.Username,
		)
	case res.GeneratedPassword != "":
		// 一次性密码必须显式 stdout —— 不进结构化日志，避免被收集
		fmt.Fprintf(stdout,
			"\n========================================\n"+
				"BOOTSTRAP ADMIN CREATED\n"+
				"  username: %s\n"+
				"  password: %s   (one-time; must change on first login)\n"+
				"========================================\n\n",
			cfg.Bootstrap.Username, res.GeneratedPassword)
		logger.Info("bootstrap admin created with random password",
			"username", cfg.Bootstrap.Username,
		)
	default:
		logger.Info("bootstrap admin created with provided password",
			"username", cfg.Bootstrap.Username,
		)
	}
	return nil
}
