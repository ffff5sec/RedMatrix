package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1/identityv1connect"
	"github.com/ffff5sec/RedMatrix/internal/config"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/identity/crypto"
	"github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
	"github.com/ffff5sec/RedMatrix/internal/identity/repo"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	rmredis "github.com/ffff5sec/RedMatrix/internal/storage/redis"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// identityHandlerMount 是 buildIdentityMount 返回的挂载信息：path + http.Handler。
type identityHandlerMount struct {
	path    string
	handler http.Handler
}

// buildIdentityMount 装配 identity 模块全栈，返回 ConnectRPC mount。
//
// 依赖（按顺序构造）：
//  1. Repos（pgxpool.App 池；后续 RLS 落地后由 tenancy interceptor 注入 session var）
//  2. JWT 服务（HS256 + cfg.Crypto.JWTSecret）
//  3. Lockout（Redis 滑窗；fail-open）
//  4. Captcha（Redis；MVP always_show=true）
//  5. AuthService（组合 1-4）
//  6. handler.Handler（适配 ConnectRPC）
//  7. identityv1connect.NewIdentityServiceHandler 产出 (path, http.Handler)
//
// 失败：任何构造步出错（密钥过短 / 配置非法等）→ 直接返错。
func buildIdentityMount(pool *pg.Pool, rds *rmredis.Client, jwtSecret string) (*identityHandlerMount, error) {
	if pool == nil || pool.App == nil {
		return nil, errx.New(errx.ErrInternal, "buildIdentityMount: pg.Pool.App 不能为 nil")
	}
	if rds == nil || rds.Client == nil {
		return nil, errx.New(errx.ErrInternal, "buildIdentityMount: redis client 不能为 nil")
	}

	users := repo.NewPG(pool.App)
	sessions := repo.NewSessionPG(pool.App)
	keys := repo.NewAPIKeyPG(pool.App)

	jwtSvc, err := crypto.NewService(jwtSecret, 0) // 0 = 默认 12h
	if err != nil {
		return nil, err
	}

	lockout, err := policy.NewRedis(rds.Client, policy.DefaultConfig())
	if err != nil {
		return nil, err
	}

	captcha, err := policy.NewRedisCaptcha(rds.Client, policy.DefaultCaptchaConfig())
	if err != nil {
		return nil, err
	}

	authSvc, err := auth.New(users, sessions, keys, jwtSvc, lockout, captcha)
	if err != nil {
		return nil, err
	}

	idHandler, err := handler.New(authSvc, captcha)
	if err != nil {
		return nil, err
	}

	path, h := identityv1connect.NewIdentityServiceHandler(idHandler)
	return &identityHandlerMount{path: path, handler: h}, nil
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
